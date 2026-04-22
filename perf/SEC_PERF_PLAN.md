# 在 KernelScript 中接入 `SEC("perf_event")` 的详细方案

## 目标

把当前这个 C 示例抽象成 KernelScript 的一等程序类型，使下面两件事都能成立：

1. 内核态可以写出等价于 `SEC("perf_event")` 的 eBPF 程序。
2. 用户态可以表达 perf event 的打开和附着语义，而不是只支持现在的 `attach(handle, target, flags)` 字符串接口。

建议按两个阶段推进，而不是一次把语言表面和运行时全部做满。

## 阶段一：最小接入，只解决 `SEC("perf_event")` 和基本签名

这一阶段的目标是“能编译出 perf_event eBPF 程序”，不强求 KernelScript 自动生成完整用户态采集器。

### 语言表面

建议先引入一个最小属性：

```kernelscript
@perf_event
fn on_branch_miss(ctx: *bpf_perf_event_data) -> i32 {
    return 0
}
```

这里建议使用 `@perf_event`，原因是：

- parser 已经支持任意 `@name` / `@name("arg")` 形式，不需要新增语法。
- 它和最终生成的 section 名 `perf_event` 一一对应，前期实现最直接。
- 等基础能力稳定后，再考虑增加更短的语法糖，例如 `@perf`。

### 需要改的编译器文件

#### 1. `src/ast.ml`

给 `program_type` 增加一个新分支，例如：

- `PerfEvent`

这是后续 type checker、IR、codegen 识别 perf_event 程序的根节点。

#### 2. `src/type_checker.ml`

需要做三件事：

- 在属性到程序类型的映射里识别 `@perf_event`。
- 给 `@perf_event` 增加签名检查。
- 让类型系统认识 `bpf_perf_event_data`。

建议的最小签名约束：

- 参数个数必须是 1。
- 参数类型必须是 `*bpf_perf_event_data`。
- 返回类型必须是 `i32`。

返回类型这里建议用 `i32`，而不是 `u32`。原因很简单：内核和 libbpf 里的 perf_event BPF 程序入口原型本质上是 `int func(struct bpf_perf_event_data *ctx)`。

### `bpf_perf_event_data` 的类型接入策略

这里建议分两步：

- 第一步把它当作可识别的上下文指针类型，只要求签名合法。
- 第二步再补字段访问支持。

也就是说，最小阶段可以先支持：

- `ctx` 可以作为参数存在。
- `ctx` 可以被传给 helper 或被忽略。
- 暂时不承诺在 KernelScript 里完整支持 `ctx->xxx` 的字段访问。

这样可以显著降低首版改动面。

#### 3. `src/ir_generator.ml`

这一层本身已经比较通用，但仍然建议补一处上下文映射：

- 在结构体名到 context 类型的映射里加入 `bpf_perf_event_data -> perf_event`。

如果阶段一不支持字段访问，这一步可以暂缓；如果希望尽早把 perf_event 上下文接入 `Context_codegen` 体系，就应该在这一步补齐。

#### 4. `src/ebpf_c_codegen.ml`

这一层必须改。核心目标有两个：

1. 让 perf_event 主函数生成正确的 section：

```c
SEC("perf_event")
int on_branch_miss(struct bpf_perf_event_data *ctx)
```

2. 让函数上下文识别逻辑知道 perf_event 是一种独立程序类型，而不是落回默认的 `SEC("prog")`。

建议修改点：

- `generate_c_function` 中生成 `section_attr` 的逻辑。
- 当前函数上下文 `current_function_context_type` 的判定逻辑。
- 初始化 context generator 的地方，如果后续引入 `perf_event_codegen`，这里也要注册。

### 阶段一不需要改的部分

#### `src/parser.mly`

不需要改。属性语法已经是泛化的：

- `@name`
- `@name("arg")`

#### `src/ir.ml`

除非存在对 `program_type` 的穷举匹配，否则通常只需要随着 `Ast.program_type` 增加新分支而被动兼容，不需要单独设计新的 IR 结构。

## 阶段二：把 perf_event 的用户态打开和附着纳入 KernelScript

这一阶段才是真正“可用”的接入。因为 `SEC("perf_event")` 只是内核态入口，真正运行还依赖用户态先调用：

1. `perf_event_open()`
2. `bpf_program__attach_perf_event()`

而当前 KernelScript 的用户态接口是：

```kernelscript
attach(handle, target, flags)
```

这个接口只适合：

- XDP：`target = "eth0"`
- tracepoint：`target = "sched/sched_switch"`
- probe：`target = "vfs_read"`

它不适合 perf_event，因为 perf_event 的附着输入不是一个字符串 target，而是一组结构化参数：

- `type`
- `config`
- `pid`
- `cpu`
- `sample_period` / `sample_freq`
- `wakeup_events`

### 建议的语言设计

这里建议不要硬塞进现有的 `attach(handle, target, flags)`，也不要把 Linux 原始的 `type: u32` / `config: u64` 直接暴露给用户。

如果语言表面直接写：

```kernelscript
struct perf_event_attr {
   type: u32,
   config: u64,
   pid: i32,
   cpu: i32,
   sample_period: u64,
   wakeup_events: u32,
}
```

那用户实际上就必须知道：

- `PERF_TYPE_HARDWARE`
- `PERF_COUNT_HW_BRANCH_MISSES`
- 哪些 `type` 和 `config` 能合法组合

这和 `SPEC.md` 现在强调的“显式但可读”不一致，也不利于做编译期校验。

更合适的做法是把 `perf_event_attr` 设计成“内建结构体符号 + 事件关键词”的组合：

```kernelscript
enum perf_counter {
   cpu_cycles,
   instructions,
   cache_references,
   cache_misses,
   branch_instructions,
   branch_misses,
   page_faults,
   context_switches,
   cpu_migrations,
}

struct perf_event_attr {
   counter: perf_counter,
   pid: i32,
   cpu: i32,
   period: u64,
   wakeup: u32,
   inherit: bool,
   exclude_kernel: bool,
   exclude_user: bool,
}

extern i32 attach_perf(handle: ProgramHandle, attr: perf_event_attr)
```

对应的 KernelScript 用法可以写成：

```kernelscript
var attr = perf_event_attr {
   counter: branch_misses,
   pid: args.pid,
   cpu: args.cpu,
   period: 1,
   wakeup: 1,
   inherit: true,
   exclude_kernel: false,
   exclude_user: false,
}

attach_perf(prog, attr)
```

这个方案的核心点是：

- 对用户暴露的是语义字段：`counter`、`pid`、`cpu`、`period`、`wakeup`
- 对编译器隐藏的是底层字段：`type`、`config`、`size`、`disabled`
- 用事件关键词把 `(type, config)` 的配对规则收敛到编译器内部

以你现在的 branch miss 示例为例，`counter: branch_misses` 在生成的 C 里就直接落回：

```c
struct perf_event_attr attr = {
   .type = PERF_TYPE_HARDWARE,
   .size = sizeof(struct perf_event_attr),
   .config = PERF_COUNT_HW_BRANCH_MISSES,
   .sample_period = cfg.period,
   .wakeup_events = cfg.wakeup,
   .disabled = 1,
   .inherit = cfg.inherit,
   .exclude_kernel = cfg.exclude_kernel,
   .exclude_user = cfg.exclude_user,
};
```

也就是说，当前 `perf/perf_user.c` 里最关键的那段 `struct perf_event_attr` 初始化代码几乎可以原样复用，只需要把 `.type/.config` 改成由 `counter` 关键词查表得到。

我建议把这个方案作为 `#sym:perf_event_attr` 的主方案，原因很直接：

- 它和 `README.md` / `SPEC.md` 现有的 `struct`、`enum`、显式字段风格一致。
- 用户看到的是 `branch_misses` 这样的领域关键词，而不是 Linux 宏常量。
- 新增事件时只需要扩一张关键词映射表，不需要改用户 API。
- 它对现有 `perf_user.c` 的复用度最高。

需要注意的一点是：第一版不要试图把 raw PMU、cache 三元组、tracepoint id 都塞进来。更稳妥的边界是：

- MVP 先支持常见计数器关键词，如 `branch_misses`、`cpu_cycles`、`instructions`
- 第二版再补高级形式，例如：
  - `raw(0x1234)`
  - `cache(l1d, read, miss)`
  - `tracepoint("sched/sched_switch")`

这样语言表面不会在第一步就变复杂。

### 需要改的文件

#### 1. `SPEC.md`

这里应该新增两个符号级文档条目：

- `#sym:perf_counter`
- `#sym:perf_event_attr`

其中：

- `#sym:perf_counter` 负责列出支持的事件关键词，例如 `branch_misses`
- `#sym:perf_event_attr` 负责列出结构体字段和语义约束

我不建议把 `type/config` 这种 Linux 原始字段写进 `#sym:perf_event_attr`，而应该把它们作为“生成后端实现细节”留在编译器内部。

#### 2. `BUILTINS.md`

补充：

- `attach_perf(...)`
- `attach_perf(...)` 的 PID/CPU 语义

否则语言表面和实现会脱节。

#### 3. `src/symbol_table.ml` / `src/type_checker.ml`

这里需要把两个内建符号接入编译器前端：

- 内建 enum：`perf_counter`
- 内建 struct：`perf_event_attr`

最小实现建议是：

- 在 symbol table 里预注册这两个类型和对应枚举常量
- 在 type checker 里允许 `perf_event_attr { ... }` 结构体字面量
- 对 `counter` 字段做枚举校验
- 对 `pid/cpu/period/wakeup` 做基础约束校验

这样 `#sym:perf_event_attr` 写出来的语言表面和编译器前端是一致的。

#### 4. `src/userspace_codegen.ml`

这是阶段二的核心改动点。

要新增的不是简单的 `case BPF_PROG_TYPE_PERF_EVENT` 分支而已，更关键的是两层逻辑：

##### 高层 builtin 翻译

把 KernelScript 中的：

- `attach_perf(handle, attr)`

翻译成用户态 C 调用，例如：

- `attach_perf_program_by_fd(handle, &attr)`

##### 底层 attach helper

在用户态 C 模板里新增类似下面的逻辑：

1. 根据 `attr.counter` 查表，生成底层的 `type/config`
2. 构造 `struct perf_event_attr`
3. 如果 `attr.pid >= 0`，走你现在 `perf_user.c` 的 `attach_all_threads_of_pid()` 路径
4. 如果 `attr.pid < 0`，校验 `attr.cpu >= 0`，然后走 `open_and_attach_one()` 路径
5. 调用 `enable_all()` 启用所有 perf fd
6. 把 `pfd` 和 `bpf_link *` 记录进 attachment registry，供 cleanup 使用

### 关于 PID 与 CPU 语义

你现在这个 C 示例实际上已经给出了很好的语义约束：

- 给定 PID 时：对该进程当前所有线程分别打开 perf event，`cpu = -1`，最终能统计线程跑到的全部 CPU。
- 不给 PID 时：必须显式给定 CPU，只监控该 CPU 的系统级事件。

如果把这套语义搬到 KernelScript，我建议直接固化为语言级约束，而不是让用户自己猜：

#### 规则

1. `pid >= 0` 时：
   - `cpu` 允许为 `-1`
   - 语义是“按线程附着，统计它实际运行到的所有 CPU”

2. `pid == -1` 时：
   - `cpu` 必须显式指定且 `>= 0`
   - 语义是“系统范围，仅监控指定 CPU”

这里我反而建议第一版就把这两种模式收敛进同一个 `attach_perf()` 里。原因是你当前的 `perf_user.c` 已经把它们组织成一个很清晰的高层语义：

- 有 `pid`：遍历 `/proc/<pid>/task`，附着到所有线程
- 无 `pid`：只附着到指定 `cpu`

这正好就是一个“高层 KernelScript builtin”应该做的事情。

如果后续确实需要更细粒度控制，再额外补一个更底层的 helper，例如：

```kernelscript
extern i32 attach_perf_one(handle: ProgramHandle, attr: perf_event_attr)
```

但在 MVP 里，没有必要先把用户 API 分裂成两个层次。

## 关于平台可用性检测

这点必须在阶段二里同步考虑，否则用户拿到的程序在某些机器上会静默失败或报错不明确。

### `perf_event_open` 的失败原因分类

`perf_event_open` 失败有五类原因，它们的处理策略完全不同：

| errno | 原因 | 处理策略 |
|-------|------|----------|
| `ENOSYS` | 内核没编译 `CONFIG_PERF_EVENTS` | 致命错误，直接终止 |
| `ENOENT` | 此 CPU/架构不支持该事件 | 致命错误，明确告知用户 |
| `EOPNOTSUPP` | 特定属性不受支持（某些 hypervisor 或 ARM 计数器） | 致命错误，或降级重试 |
| `EACCES` | 权限不足，通常是 `perf_event_paranoid` 太高 | 可恢复，提示用户如何调整 |
| `EMFILE` / `ENOMEM` | 资源耗尽 | 可恢复，减少附着数量 |

### 语言层设计：`check_perf_support` builtin

在 `attach_perf(handle, attr)` 之前，建议额外提供一个"干跑"检测 builtin：

```kernelscript
extern i32 check_perf_support(attr: perf_event_attr) -> i32
```

它的作用是：用同一个 `perf_event_attr` 先开一个 fd，立刻关掉，只验证系统是否支持——不做任何 BPF 附着。返回 0 表示支持，返回负 errno 表示不支持及原因。

典型用法：

```kernelscript
fn main(args: Args) -> i32 {
    var attr = perf_event_attr {
        counter: branch_misses,
        pid: args.pid,
        cpu: args.cpu,
        period: 1,
        wakeup: 1,
        inherit: true,
        exclude_kernel: false,
        exclude_user: false,
    }

    try {
        check_perf_support(attr)
        var prog = load(on_branch_miss)
        attach_perf(prog, attr)
    } catch -95 {                    // -EOPNOTSUPP
        print("perf event not supported on this CPU/hypervisor")
        return 1
    } catch -2 {                     // -ENOENT
        print("hardware counter 'branch_misses' not available")
        return 1
    } catch -1 {                     // -EPERM / -EACCES
        print("permission denied: try 'echo -1 > /proc/sys/kernel/perf_event_paranoid'")
        return 1
    }
    return 0
}
```

这样错误处理就和 KernelScript 现有的 `try/catch` 风格完全一致。

### 生成 C 的行为规则

在 `userspace_codegen.ml` 生成的 `check_perf_support` 实现里，核心逻辑应该是：

```c
static int check_perf_support(struct perf_event_ks_attr *ks_attr)
{
    struct perf_event_attr attr = /* 由 ks_attr->counter 查表填充 */;
    int pfd;

    /* 用 pid=0 cpu=0 做最保守的探测：仅探测当前线程在 cpu0 上是否可以采样 */
    pfd = syscall(__NR_perf_event_open, &attr, 0, 0, -1, 0);
    if (pfd < 0) {
        return -errno;   /* 直接返回负 errno，调用方按 KernelScript catch 分支处理 */
    }
    close(pfd);
    return 0;
}
```

注意这里用 `pid=0, cpu=0`（当前进程 + CPU 0）做探测，而不是用最终目标 pid/cpu，这样可以避免当目标 pid 不存在时的干扰。

### `perf_event_paranoid` 的运行时提示

`EACCES` 是最常见的用户端问题。`attach_perf` 的生成代码里，如果碰到 `errno == EACCES`，应该读取 `/proc/sys/kernel/perf_event_paranoid`，根据它的值给出具体建议：

| paranoid 值 | 含义 | 建议 |
|-------------|------|------|
| `-1` | 允许所有用户 | 不会出现此错误 |
| `0` | 允许所有用户访问 CPU 级别事件 | 不会出现此错误 |
| `1`（默认） | 普通用户只可访问进程级别事件 | 以 root 或 `CAP_PERFMON` 运行 |
| `2` | 只允许 root | 以 root 运行 |
| `3` | 完全禁止 | `echo 0 > /proc/sys/kernel/perf_event_paranoid` |

这个表可以直接硬编码进生成的 C helper 里，出错时打印到 stderr。

### 内建符号的可用性标注

回到 `#sym:perf_event_attr` / `#sym:perf_counter` 的文档设计，每个事件关键词应该附带一个"可用性"列，例如：

| 关键词 | 底层映射 | 架构覆盖 | 虚拟机支持 |
|--------|----------|----------|------------|
| `cpu_cycles` | `PERF_TYPE_HARDWARE / PERF_COUNT_HW_CPU_CYCLES` | x86、ARM | 部分 |
| `instructions` | `PERF_TYPE_HARDWARE / PERF_COUNT_HW_INSTRUCTIONS` | x86、ARM | 部分 |
| `branch_misses` | `PERF_TYPE_HARDWARE / PERF_COUNT_HW_BRANCH_MISSES` | x86、ARM | 少数支持 |
| `page_faults` | `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_PAGE_FAULTS` | 全部 | 是 |
| `context_switches` | `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CONTEXT_SWITCHES` | 全部 | 是 |
| `cpu_migrations` | `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_MIGRATIONS` | 全部 | 是 |

这里有个重要区分：

- `PERF_TYPE_HARDWARE` 类型的事件依赖硬件 PMU，在 KVM 默认配置、某些云主机里会返回 `ENOENT` 或 `EOPNOTSUPP`。
- `PERF_TYPE_SOFTWARE` 类型的事件完全由内核实现，几乎所有环境下都可用。

建议把 `page_faults`、`context_switches`、`cpu_migrations` 归为"软件计数器"子组，在文档里标注为"兼容性最好，适合作为 fallback"。

### 当前 `perf/perf_user.c` 里需要补的部分

当前的 `perf_user.c` 里 `open_and_attach_one` 已经打印了 `perf_event_open` 的错误，但没有区分错误原因。建议在 `sys_perf_event_open` 调用失败后加一段：

```c
if (pfd < 0) {
    if (errno == ENOSYS)
        fprintf(stderr, "perf_event_open: kernel does not support perf events "
                        "(CONFIG_PERF_EVENTS not set)\n");
    else if (errno == ENOENT)
        fprintf(stderr, "perf_event_open: hardware event not available on this "
                        "CPU/architecture\n");
    else if (errno == EOPNOTSUPP)
        fprintf(stderr, "perf_event_open: event attribute not supported "
                        "(try running on bare metal instead of VM)\n");
    else if (errno == EACCES) {
        int paranoid = read_perf_event_paranoid();
        fprintf(stderr, "perf_event_open: permission denied "
                        "(perf_event_paranoid=%d, try running as root or "
                        "'echo 0 > /proc/sys/kernel/perf_event_paranoid')\n",
                paranoid);
    } else {
        fprintf(stderr, "perf_event_open(pid=%d, cpu=%d) failed: %s\n",
                pid, cpu, strerror(errno));
    }
    return -1;
}
```

其中 `read_perf_event_paranoid()` 就是读取 `/proc/sys/kernel/perf_event_paranoid` 的简单辅助函数。

## 阶段三：把 perf_event 上下文字段访问做完整

如果你只想先支持 `ctx` 传参或忽略，这一阶段可以后做。

但如果希望在 KernelScript 里直接写：

```kernelscript
var addr = ctx->addr
```

那就需要把 perf_event 上下文并入现有的 `src/context/` 体系。

### 建议新增文件

- `src/context/perf_event_codegen.ml`

### 需要做的事

1. 注册一个新的 context type，例如 `"perf_event"`
2. 提供：
   - `c_type`
   - `section_prefix`
   - `generate_section_name`
   - `field_mappings`

其中 `generate_section_name` 很简单，直接返回：

- `SEC("perf_event")`

### 字段映射策略

建议首版只支持你真正需要的少量字段，而不是一口气把所有字段都补满。

最小字段集建议先支持：

- `sample_period`
- `addr`

如果后续需要读调用栈、寄存器、采样地址，再继续扩。

## 阶段四：文档与示例

实现结束后至少要补三样东西：

### 1. `BUILTINS.md`

新增 perf_event 用户态 API 文档。

### 2. `examples/`

新增一个最小例子，例如：

- `examples/perf_branch_miss.ks`

建议内容分成两部分：

- 一个 `@perf_event` 内核态函数
- 一个 userspace `main()`，演示 `attach_perf()` 在 PID 模式和 CPU 模式下的两种用法

### 3. `README.md` 或 `SPEC.md`

把支持的 eBPF 程序类型列表补上 perf_event。

## 建议的落地顺序

最稳妥的实施顺序如下：

1. `ast.ml` 增加 `PerfEvent`
2. `type_checker.ml` 识别 `@perf_event` 并校验签名
3. `ebpf_c_codegen.ml` 生成 `SEC("perf_event")`
4. 先做一个只生成 eBPF C 的最小例子，验证 section 和函数签名正确
5. 再把 `perf_counter` / `perf_event_attr` 作为内建符号接进前端
6. 设计 `attach_perf(...)` 的 builtin 接口
7. 在 `userspace_codegen.ml` 里复用当前 `perf_user.c` 的 attach 逻辑
7. 最后再做 `perf_event_codegen.ml` 的字段访问增强

## 最小可交付版本与完整版本的界线

### 最小可交付版本

满足以下条件就算阶段性完成：

- KernelScript 能写 `@perf_event`
- 编译器能产出 `SEC("perf_event")` 的 eBPF C
- 函数签名合法
- 用户态仍可手写 C 加载器

### 完整版本

要达到“像 XDP / tracepoint 一样真正一等支持”，还必须再补：

- perf event 专用 userspace builtin
- perf event 的 attach helper
- PID / CPU 语义约束
- context 字段访问
- 官方示例与文档

这也是我建议分阶段做的原因：`SEC("perf_event")` 本身不难，真正复杂的是把 perf_event 的用户态生命周期管理也纳入 KernelScript。 