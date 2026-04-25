# perf_event_attr 说明

这个文档描述当前 KernelScript 中 perf_event_attr 的已实现形态，重点是 attach(handle, perf_event_attr) 这一条 userspace 生成链路，而不是最初的设计草案。

## 当前入口

当前语言侧写法如下：

```kernelscript
@perf_event
fn on_branch_miss(ctx: *bpf_perf_event_data) -> i32 {
    return 0
}

fn main() -> i32 {
    var attr = perf_event_attr {
        counter: branch_misses,
        pid: -1,
        cpu: 0,
        period: 1000000,
        wakeup: 1,
        inherit: false,
        exclude_kernel: false,
        exclude_user: false
    }

    var prog = load(on_branch_miss)
    attach(prog, attr)
    detach(prog)
    return 0
}
```

当前实现里，attach(prog, attr) 会在 userspace C 中被翻译成 attach_perf_by_attr(prog_fd, ks_perf_event_attr)。

## perf_counter 映射

内建 perf_counter 当前支持 9 个计数器，生成时会被映射到 Linux perf_event 的 type/config 组合。

| KernelScript | Linux type | Linux config | 类别 |
| --- | --- | --- | --- |
| cpu_cycles | PERF_TYPE_HARDWARE | PERF_COUNT_HW_CPU_CYCLES | 硬件 |
| instructions | PERF_TYPE_HARDWARE | PERF_COUNT_HW_INSTRUCTIONS | 硬件 |
| cache_references | PERF_TYPE_HARDWARE | PERF_COUNT_HW_CACHE_REFERENCES | 硬件 |
| cache_misses | PERF_TYPE_HARDWARE | PERF_COUNT_HW_CACHE_MISSES | 硬件 |
| branch_instructions | PERF_TYPE_HARDWARE | PERF_COUNT_HW_BRANCH_INSTRUCTIONS | 硬件 |
| branch_misses | PERF_TYPE_HARDWARE | PERF_COUNT_HW_BRANCH_MISSES | 硬件 |
| page_faults | PERF_TYPE_SOFTWARE | PERF_COUNT_SW_PAGE_FAULTS | 软件 |
| context_switches | PERF_TYPE_SOFTWARE | PERF_COUNT_SW_CONTEXT_SWITCHES | 软件 |
| cpu_migrations | PERF_TYPE_SOFTWARE | PERF_COUNT_SW_CPU_MIGRATIONS | 软件 |

经验上，软件计数器兼容性更高；硬件计数器在 VM、云主机或没有 PMU 直通的环境里更容易失败。

## perf_event_attr 字段

当前内建结构体如下：

| 字段 | 类型 | 当前语义 |
| --- | --- | --- |
| counter | perf_counter | 要监控的 perf 计数器 |
| pid | i32 | 原样传给 perf_event_open |
| cpu | i32 | 允许 `-1` 或 `>= 0`；当 `pid == -1` 时必须显式给出 `>= 0` 的 CPU |
| period | u64 | 生成 sample_period，0 时默认回退到 1000000 |
| wakeup | u32 | 生成 wakeup_events，0 时默认回退到 1 |
| inherit | bool | 生成 inherit |
| exclude_kernel | bool | 生成 exclude_kernel |
| exclude_user | bool | 生成 exclude_user |

当前 userspace 生成器的运行时约束是：

1. `pid < -1` 会直接报错。
2. `cpu < -1` 会直接报错。
3. `pid == -1 && cpu == -1` 会直接报错，因为系统范围采样必须显式指定 CPU。
4. `pid >= 0 && cpu == -1` 会原样传给 `perf_event_open`，可以表达“指定线程，任意 CPU”模式。

## 生成后的 userspace 行为

当前 attach_perf_by_attr 的执行顺序是：

1. 校验 prog_fd 是否有效，以及该程序是否已被跟踪为已附着。
2. 把 counter 映射成 PERF_TYPE_* 和 PERF_COUNT_*。
3. 构造 struct perf_event_attr。
4. 调用 perf_event_open 打开一个 perf fd。
5. 从 skeleton 中找回 bpf_program。
6. 调用 bpf_program__attach_perf_event 建立 bpf_link。
7. 调用 PERF_EVENT_IOC_RESET 和 PERF_EVENT_IOC_ENABLE 启用事件。
8. 把 bpf_link 和 perf fd 一起记入 attachment registry，供 detach(handle) 清理。

当前 detach(handle) 在 perf_event 分支会：

1. 先尝试 PERF_EVENT_IOC_DISABLE。
2. destroy bpf_link。
3. close perf fd。
4. 从 attachment registry 中移除该项。

这意味着当前工作树已经补齐了 perf_event 的基础资源回收，不再只销毁 link 而泄漏 perf fd。

## 当前边界

当前实现已经能表达最小的 perf_event userspace 生命周期，但仍有几个明确边界：

1. 一次 attach(prog, attr) 只会打开一个 perf_event fd，不会像独立的 perf/perf_user.c 那样按 PID 枚举所有线程。
2. `pid >= 0 && cpu == -1` 现在是单线程语义，不是“遍历整个进程所有线程”的 fan-out 语义。
3. 当前还没有 multiplex 归一化、event groups、统一读数导出这些更完整的 perf runtime 能力。
4. 文档和示例已经有最小闭环，但更细的权限诊断、兼容性提示和 PID fan-out 封装还没有进入 KernelScript 生成路径。

## 相关文件

- src/stdlib.ml: 内建 perf_counter 和 perf_event_attr 定义
- src/userspace_codegen.ml: attach(prog, perf_event_attr) 的 userspace C 生成逻辑
- examples/perf_branch_miss.ks: 最小 KernelScript 示例
- examples/perf_branch_miss/perf_branch_miss.c: 当前生成出的 userspace 示例