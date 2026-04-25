# perf_event 后续方案

这个方案基于最近三次提交整理：

- 6d165a7: Add support for perf_event programs in KernelScript
- 24ebed2: 修复 perf_event 示例主函数参数，并补齐 userspace codegen 的 attach/detach 路径
- 29f04ef: 把 attach 统一成 attach(handle, perf_event_attr)，移除 attach_perf，更新测试

## 最近三次提交已经完成的部分

### 第一阶段：程序类型接入

6d165a7 把 perf_event 作为一等程序类型接进了编译器主链路：

- 前端可以识别 @perf_event。
- eBPF 代码生成能产出 SEC("perf_event")。
- 标准库增加了 perf_counter 和 perf_event_attr。
- 示例和独立 perf 目录初步落地。

### 第二阶段：userspace 生命周期最小闭环

24ebed2 把 userspace 侧补成了可跑通的最小路径：

- 生成器开始为 perf_event 生成 attach 和 detach 支持。
- 示例 main 签名回到编译器预期形态。
- examples/perf_branch_miss.ks 能生成最小的 load/attach 路径。

### 第三阶段：接口收敛到 attach

29f04ef 做了最重要的 API 收敛：

- 不再保留 attach_perf 这个单独 builtin。
- attach(handle, perf_event_attr) 成为统一入口。
- 相关测试同步到 attach 的双形态校验。

## 当前状态评估

现在这条链路已经具备“可编译、可生成、可附着、可分离”的最小闭环，但它仍然更像 MVP，而不是完整的 perf_event 运行时。

当前工作树已经额外补掉了两处近期回归风险：

- perf_event detach 现在会同时关闭 perf fd，不再只销毁 bpf_link。
- attach 跟踪失败时不再返回假成功，也不会把 link/fd 留成孤儿资源。

## 还需要补的点

### 1. 扩展 pid/cpu 语义到 PID fan-out

当前工作树已经把最小语义收敛到了运行时校验层：

- `pid >= 0 && cpu == -1` 会原样传给 `perf_event_open`
- `pid == -1 && cpu == -1` 会直接报错
- `pid < -1` 和 `cpu < -1` 会直接报错

但这仍然没有达到独立示例 `perf/perf_user.c` 的 PID fan-out 行为。

建议：

1. 决定 `pid >= 0` 时是否要自动遍历 `/proc/<pid>/task`。
2. 如果要支持 fan-out，就把 attachment registry 扩成一组 perf fd/bpf_link。
3. 如果不支持 fan-out，就把“单线程 attach”语义明确写进语言文档和错误消息。

### 2. 决定是否支持 PID fan-out

当前 attach(prog, perf_event_attr) 只打开一个 perf fd，而 perf/perf_user.c 已经有按 PID 遍历线程的实现思路。

建议：

1. 明确 KernelScript 的 attach(prog, attr) 是“单 event attach”还是“按 PID fan-out attach”。
2. 如果要支持 fan-out，就把 attachment registry 从一条记录扩成一组 perf fd/bpf_link。
3. 给 detach(handle) 定义成完整回收整组资源，而不是只回收一个 fd。

### 3. 补齐测试矩阵

当前测试主要覆盖类型和 builtin 识别，还缺几类关键回归测试：

1. attach(handle, perf_event_attr) 生成的 userspace C 里确实包含 perf_event_open 和 attach_perf_by_attr。
2. detach(handle) 在 perf_event 分支会关闭 perf fd。
3. pid/cpu 的非法组合能给出稳定错误。
4. 同一个 ProgramHandle 重复 attach 会返回错误而不是覆盖状态。

### 4. 继续收敛 attachment 模板

当前工作树已经把 kprobe、tracepoint、tracing、tcx 的 link 错误检查统一成了 libbpf_get_error(link)，但 attachment 模板仍然有重复代码。

建议：

1. 统一 add_attachment 失败后的回滚逻辑。
2. 给 attachment helper 增加一组共享的小工具，减少重复模板代码。
3. 把 link 错误字符串格式收成一个共用 helper，避免分支复制。

### 5. 文档收口

现在设计草案、示例 README 和实现现状之间还有轻微偏差，尤其是 PID 语义和 cpu 负值处理。

建议：

1. 以 perf/PERF_ATTR.md 作为“当前实现说明”。
2. 保留 perf/SEC_PERF_PLAN.md 作为设计演进草案。
3. 在 BUILTINS.md 中把 attach 的两种签名都写清楚，并明确 perf_event_attr 的跳转文档。

### 6. Future Work: multiplex 与更完整的 perf runtime

当前实现还是“单 counter、单 fd、单 link”的最小路径，距离真正可长期运行的 perf runtime 还有一段距离。下一批 future work 建议单独规划成下面几类能力。

#### 6.1 counter multiplex

当用户同时打开的硬件计数器多于 PMU 物理槽位时，内核会进入 multiplex 模式。此时如果只看原始计数值，结果会偏小，必须结合 `time_enabled` 和 `time_running` 做归一化。

建议：

1. 为 `perf_event_attr` 增加“允许 multiplex”或“要求归一化输出”的高层开关，而不是把 `read_format` 细节直接暴露给用户。
2. userspace helper 在打开 perf event 时启用 `PERF_FORMAT_TOTAL_TIME_ENABLED` 和 `PERF_FORMAT_TOTAL_TIME_RUNNING`。
3. 如果发生 multiplex，就在生成的 userspace runtime 里把读数转换成归一化值，避免用户误把原始值当成真实计数。
4. 对于不支持归一化的路径，至少在 stderr 或日志里明确提示“当前计数处于 multiplex 状态”。

#### 6.2 event groups 与 leader/follower 语义

很多实际场景不会只采一个 counter，而是需要把 `cycles`、`instructions`、`branch_misses` 放进同一组，确保它们的启停和读数窗口一致。

建议：

1. 设计高层 group API，例如让一组 `perf_event_attr` 在同一个 group leader 下打开。
2. 在 attachment registry 中把单个 `perf_fd` 扩成“event group 记录”，便于整组 enable、disable、detach。
3. 为后续 IPC、CPI、branch miss ratio 这类派生指标预留统一计算入口。

#### 6.3 读取路径与结果导出

当前实现只负责 attach/detach，不负责统一读取结果。后续如果要把 perf_event 作为长期能力用起来，必须补读取和导出路径。

建议：

1. 明确是走 `read(perf_fd, ...)`、mmap ring buffer，还是只把 eBPF 程序当作 overflow hook。
2. 如果要支持 userspace 读数，设计统一的数据结构，至少包含 raw count、normalized count、time_enabled、time_running。
3. 如果要支持 eBPF 侧输出，明确 map、ringbuf、per-cpu aggregation 三种模式的边界。

#### 6.4 sample_period 与 sample_freq 模式

当前高层接口只有 `period`，还没有覆盖 `sample_freq`、`watermark`、更细粒度 wakeup 策略。

建议：

1. 评估是否要在语言层增加 `frequency` 模式，而不是让用户自己切 raw perf flags。
2. 区分“计数模式”和“采样模式”，避免同一个字段承担两种不同语义。
3. 给高频采样路径增加默认保护，避免用户无意中生成过载配置。

#### 6.5 CPU hotplug、thread churn 与重附着

现在的最小实现没有覆盖 CPU hotplug，也没有覆盖 PID fan-out 下线程动态增减的重附着。

建议：

1. 如果未来支持 PID fan-out，需要决定线程新建时是自动补附着，还是由用户显式 refresh。
2. 如果支持 system-wide CPU 模式，需要考虑 CPU 上下线后的 perf fd 重建。
3. 这些重附着逻辑应与 attachment registry 统一建模，否则 cleanup 会变得很脆。

#### 6.6 兼容性与降级策略

硬件 PMU 能力高度依赖平台，multiplex、虚拟化、权限模型也会影响可用性。

建议：

1. 为 `branch_misses` 这类硬件计数器提供更明确的 capability 探测。
2. 在不支持硬件 PMU 时，允许回退到 `page_faults`、`context_switches` 这类软件 counter。
3. 把权限、虚拟化限制、multiplex 警告统一收敛到一套 runtime diagnostics。

## 推荐执行顺序

1. 先决定是否引入 PID fan-out；这会直接影响 attachment registry 结构。
2. 然后补更高一层的语义测试，锁住生成代码和 fan-out 行为。
3. 再决定 multiplex 和 event groups 是不是要进第一版可用 runtime。
4. 最后继续收 attachment helper 的重复模板代码，并把 diagnostics 与结果导出一起补齐。