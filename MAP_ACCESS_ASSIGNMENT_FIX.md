# Map Access Assignment 一致性修复

## 问题描述

在 eBPF C 代码生成中，map lookup 操作在不同上下文中生成的代码不一致：
在ringbuf_demo中
### 问题表现

**变量声明时的 map access：**
```javascript
var stat = stats[key]
```
生成的 C 代码（正确）：
```c
struct Stats stat = ({ 
    struct Stats __val = {0}; 
    if (__map_lookup_0) { 
        __val = *(__map_lookup_0); 
    } 
    __val; 
});
```

**赋值语句中的 map access：**
```javascript
stat = stats[key]
```
生成的 C 代码（错误）：
```c
stat = __map_lookup_3;  // 错误：将指针赋值给值类型变量
```

### 影响

这导致类型不匹配，`stat` 变量声明为 `struct Stats` 值类型，但第二次赋值却赋予了 `struct Stats*` 指针类型，违反了 KernelScript 的值语义。

## 根本原因

在 `src/ebpf_c_codegen.ml` 的 `generate_assignment` 函数中，处理简单值赋值时：

1. **变量声明路径**（line 1921）：
   - 使用 `generate_c_expression` 
   - 该函数会自动检测 `IRMapAccess` 并设置 `auto_deref_map_access:true`（line 1403）
   - 结果：正确生成解引用代码

2. **赋值语句路径**（line 2547）：
   - 直接使用 `generate_c_value` 
   - 没有设置 `auto_deref_map_access` 标志
   - 结果：返回原始指针，未解引用

## 修复方案

### 代码变更

**文件：** `src/ebpf_c_codegen.ml`

**位置：** `generate_assignment` 函数，第 2542-2549 行

**修改前：**
```ocaml
| IRValue src_val ->
    (* Simple value assignment *)
    let dest_str = generate_c_value ctx dest_val in
    let src_str = generate_c_value ctx src_val in
    emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str src_str)
```

**修改后：**
```ocaml
| IRValue src_val ->
    (* Simple value assignment *)
    let dest_str = generate_c_value ctx dest_val in
    (* Auto-dereference map access to get the value, not the pointer *)
    let src_str = (match src_val.value_desc with
      | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx src_val
      | _ -> generate_c_value ctx src_val) in
    emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str src_str)
```

### 修复效果

修复后，赋值语句中的 map access 也会生成正确的解引用代码：

```c
stat = ({ 
    struct Stats __val = {0}; 
    if (__map_lookup_3) { 
        __val = *(__map_lookup_3); 
    } 
    __val; 
});
```

## 影响范围

### 受影响的代码模式

所有在赋值语句右侧使用 map lookup 的情况：

```javascript
// 模式 1：直接赋值
var value = map[key]
value = map[another_key]  // ← 此处受影响

// 模式 2：if 块中的赋值
if (condition) {
    value = map[key]  // ← 此处受影响
}

// 模式 3：字段访问后的赋值
var obj = map[key]
obj = map[new_key]  // ← 此处受影响
```

### 不受影响的情况

以下情况在修复前就是正确的：

1. 变量声明 `var x = map[key]`
2. 函数调用参数 `func(map[key])`
3. 表达式中的 map access `if (map[key] == x)`
4. return 语句 `return map[key]`

## 语义保证

此修复确保 KernelScript 的**值语义**在所有上下文中保持一致：

1. **KernelScript 层面**：`map[key]` 表示获取 map 中的值（value semantics）
2. **eBPF C 层面**：`bpf_map_lookup_elem` 返回指针（pointer semantics）
3. **代码生成**：自动插入安全的解引用操作，包含 NULL 检查

生成的代码模式：
```c
({ 
    ValueType __val = {0};      // 默认初始化为零值
    if (pointer) {               // NULL 检查
        __val = *(pointer);      // 安全解引用
    } 
    __val;                       // 返回值类型
})
```

## 测试建议

### 编译测试

```bash
cd /home/ssy/kernelscript
dune build
```

### 功能测试

使用 `examples/ringbuf_demo.ks` 验证：

```bash
# 重新生成 C 代码
./_build/default/src/main.exe examples/ringbuf_demo.ks

# 检查生成的 eBPF C 代码
grep -A 5 "stat = " examples/ringbuf_demo/ringbuf_demo.ebpf.c
```

**预期结果：** 所有 `stat = stats[key]` 生成的代码应该一致，都包含解引用逻辑。

### 回归测试

运行完整测试套件确保没有引入新问题：

```bash
dune test
```

## 版本信息

- **修复日期：** 2026-03-05
- **受影响版本：** 所有使用 map access 赋值的版本
- **修复分支：** test
- **相关文件：** 
  - `src/ebpf_c_codegen.ml` (修复)
  - `examples/ringbuf_demo.ks` (测试用例)

## 相关问题

此修复解决了代码生成不一致性问题，属于以下类别：

- 🐛 **Bug Fix**: 修复类型不匹配错误
- 🔧 **Code Generation**: eBPF C 代码生成改进
- ✅ **Type Safety**: 增强类型安全性保证
- 📖 **Semantics**: 确保语义一致性

## 检查清单

- [x] 识别问题根源
- [x] 实施代码修复
- [x] 添加内联注释说明修改原因
- [x] 编写 patch 说明文档
- [ ] 执行编译测试
- [ ] 验证生成的 C 代码
- [ ] 运行回归测试
- [ ] 更新相关文档（如需要）
