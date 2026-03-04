# Pin Map 错误修复

## 问题描述

使用 `pin` 关键字声明的 maps 存在两个问题：

1. **错误地当作 pinned global variables 处理**，导致错误：
   ```
   Failed to find pinned globals map in eBPF object
   ```

2. **Pinned maps 的 setup 代码没有生成**，导致 maps 没有被正确 pin 到文件系统

### 根本原因

#### 问题 1：Map 被当作全局变量

在 IR 生成器中，当处理 map 类型的全局变量声明（例如 `pin var cpu_counters : array<u32, Counter>(256)`）时，代码同时创建了：

1. **IR map 定义** (`ir_map`) - 正确
2. **IR 全局变量** (`ir_var`) - **错误**

这导致在 userspace 代码生成时：
- `generate_pinned_globals_support` 看到这些"全局变量"（实际上是 maps）
- 将它们错误地添加到 `pinned_globals_struct` 中
- 尝试查找不存在的 `__pinned_globals` map

#### 问题 2：Pinned maps setup 代码未生成

在 `userspace_codegen.ml` 中，map setup 代码只在以下条件时生成：
- `all_usage.uses_map_operations` - userspace 代码使用 map 操作
- `all_usage.uses_exec` - userspace 代码使用 exec()

但是对于 **pinned maps**，即使 userspace 不直接访问它们（例如 maps 只在 eBPF 程序中使用），也需要生成 setup 代码来执行 pinning 操作到 `/sys/fs/bpf/<PROJECT_NAME>/maps/<MAP_NAME>`。

### Pin 机制的区别

系统支持两种不同的 pinning 机制：

1. **Pinned Maps** (如 `pin var cpu_counters : array<...>`)
   - 每个 map 单独 pin 到 `/sys/fs/bpf/<PROJECT_NAME>/maps/<MAP_NAME>`
   - 在 eBPF 侧生成普通的 BPF map 定义
   - 在 userspace 侧通过 `bpf_map__pin()` 单独 pin

2. **Pinned Global Variables** (如 `pin var counter: u32 = 0`)
   - 所有 pinned 全局变量存储在一个特殊的 `__pinned_globals` map 中
   - 该 map 作为单个 ARRAY map pin 到 `/sys/fs/bpf/<PROJECT_NAME>/globals/pinned_globals`
   - 通过 map 操作访问这些变量

## 修复方案

### 修改 1: ir_generator.ml - 不为 map 类型创建全局变量

```ocaml
| Ast.GlobalVarDecl var_decl when is_global_var_map var_decl ->
    (* When a global variable has a map type, convert it to a map definition only.
       Do NOT create a corresponding IR global variable, as that causes the map
       to be incorrectly treated as a pinned global variable in userspace codegen. *)
    let ir_map = match convert_global_var_to_map symbol_table var_decl with
      | Some map -> map
      | None -> failwith "Expected map conversion to succeed"
    in
    (* Only track as map, not as global variable *)
    ((decl, `MapFromGlobalVar ir_map) :: decls, ir_map :: maps, vars)
```

### 修改 2: ir_generator.ml - 更新声明处理

```ocaml
| `MapFromGlobalVar ir_map ->
    (* For global variables with map types, only add the map definition.
       Do NOT add a global variable declaration, as it would incorrectly be treated
       as a pinned global variable in userspace codegen. *)
    add_source_declaration (IRDeclMapDef ir_map) pos
```

### 修改 3: userspace_codegen.ml - 确保 pinned maps 的 setup 代码生成

```ocaml
(* Generate setup code first for use in main function *)
(* Check if there are any pinned maps that need setup *)
let has_pinned_maps = List.exists (fun map -> map.pin_path <> None) global_maps in
let map_setup_code = if all_usage.uses_map_operations || all_usage.uses_exec || has_pinned_maps then
  (* For pinned maps, we need to include all of them in setup, not just used ones *)
  let maps_for_setup = if has_pinned_maps then global_maps else used_global_maps_with_exec in
  generate_unified_map_setup_code maps_for_setup
else "" in
```

### 修改 4: userspace_codegen.ml - 确保 pinned maps 的 FD 声明生成

```ocaml
let map_fd_declarations = if all_usage.uses_map_operations || all_usage.uses_exec || has_pinned_maps then
  let maps_for_fd = if has_pinned_maps then global_maps else used_global_maps_with_exec in
  generate_map_fd_declarations maps_for_fd
else "" in
```

### 修改 5: userspace_codegen.ml - 在 main 函数中包含 pinned maps setup

```ocaml
(* Check if there are any pinned maps that need setup *)
let has_pinned_maps = match ir_multi_prog with
  | Some multi_prog -> List.exists (fun map -> map.pin_path <> None) (Ir.get_global_maps multi_prog)
  | None -> false
in

let setup_call = if needs_object_loading && (...|| has_pinned_maps) then
  (* Include all_setup_code for maps (including pinned maps), config, struct_ops, and ringbuf *)
  (if ... || has_pinned_maps then all_setup_code else "");
```

### 修改 6: userspace_codegen.ml - 为每个 map 生成唯一的 existing_fd 变量名

修复了多个 pinned maps 导致的 `existing_fd` 变量重定义错误：

```ocaml
(* Generate unique variable name for each map's existing_fd *)
Printf.sprintf {|
    // Check if map is already pinned
    int %s_existing_fd = bpf_obj_get("%s");
    if (%s_existing_fd >= 0) {
        %s_fd = %s_existing_fd;
    ...
|} map.map_name pin_path map.map_name map.map_name map.map_name
```

### 修改 7: userspace_codegen.ml - 添加目录创建辅助函数

在 pin map 之前，需要确保 BPF 文件系统的目录结构存在：

```ocaml
(* Generate directory creation helper if there are pinned maps *)
let mkdir_helper_function = if has_pinned_maps then
  {|// Helper function to create directory recursively
static int ensure_bpf_dir(const char *path) {
    char tmp[256];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}|}
else "" in
```

在 pin map 之前调用：
```c
if (ensure_bpf_dir("/sys/fs/bpf/maps_demo/maps") < 0) {
    fprintf(stderr, "Failed to create directory /sys/fs/bpf/maps_demo/maps: %s\n", strerror(errno));
    return 1;
}
```

### 修改 8: userspace_codegen.ml - 添加必要的头文件

确保包含目录操作所需的头文件：

```ocaml
let pinning_headers = if has_pinned_maps then [
  "#include <sys/stat.h>";
  "#include <sys/types.h>";
] else [] in
```

## 效果

修复后：
- Map 类型的全局变量只生成 IR map 定义
- `Ir.get_global_variables()` 不再返回这些 maps
- `generate_pinned_globals_support()` 只处理真正的全局变量
- 即使 userspace 代码不直接使用 maps，pinned maps 的 setup 代码仍然会生成
- 每个 pinned map 正确 pin 到 `/sys/fs/bpf/<PROJECT_NAME>/maps/<MAP_NAME>`
- Map FD 声明和 setup 代码都会被生成

## 生成的代码示例

对于 `pin var cpu_counters : array<u32, Counter>(256)`，会生成：

```c
// 辅助函数（只生成一次，供所有 pinned maps 使用）
// Helper function to create directory recursively
static int ensure_bpf_dir(const char *path) {
    char tmp[256];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

// FD 声明
int cpu_counters_fd = -1;

// Setup 代码（在 main 函数中）
// Load map cpu_counters from eBPF object
struct bpf_map *cpu_counters_map = bpf_object__find_map_by_name(obj->obj, "cpu_counters");
if (!cpu_counters_map) {
    fprintf(stderr, "Failed to find cpu_counters map in eBPF object\n");
    return 1;
}
// Check if map is already pinned
int cpu_counters_existing_fd = bpf_obj_get("/sys/fs/bpf/maps_demo/maps/cpu_counters");
if (cpu_counters_existing_fd >= 0) {
    cpu_counters_fd = cpu_counters_existing_fd;
} else {
    // Map not pinned yet, create directory and pin it
    if (ensure_bpf_dir("/sys/fs/bpf/maps_demo/maps") < 0) {
        fprintf(stderr, "Failed to create directory /sys/fs/bpf/maps_demo/maps: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_map__pin(cpu_counters_map, "/sys/fs/bpf/maps_demo/maps/cpu_counters") < 0) {
        fprintf(stderr, "Failed to pin cpu_counters map to /sys/fs/bpf/maps_demo/maps/cpu_counters\n");
        return 1;
    }
    cpu_counters_fd = bpf_map__fd(cpu_counters_map);
}
if (cpu_counters_fd < 0) {
    fprintf(stderr, "Failed to get fd for cpu_counters map\n");
    return 1;
}
```

注意：
- `ensure_bpf_dir` 辅助函数只生成一次，供所有 pinned maps 使用
- 每个 map 都有自己唯一的 `{map_name}_existing_fd` 变量，避免变量重定义错误
- 在 pin map 之前会先创建目录结构
- 已包含必要的头文件 `<sys/stat.h>` 和 `<sys/types.h>`

## 测试

使用 `examples/maps_demo.ks` 测试：

```bash
cd /home/ssy/kernelscript
dune build
./_build/default/src/main.exe examples/maps_demo.ks
cd examples/maps_demo
make
sudo ./maps_demo
```

预期结果：
- 不再出现 "Failed to find pinned globals map in eBPF object" 错误
- Maps 正确 pin 到 `/sys/fs/bpf/maps_demo/maps/<map_name>`
- 程序正常运行
- 可以验证 pinned maps：`sudo ls -la /sys/fs/bpf/maps_demo/maps/`

