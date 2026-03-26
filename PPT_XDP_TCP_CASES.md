# KernelScript 案例页：XDP 包过滤与 TCP 拥塞控制

这份文档面向 PPT 使用，选两个最容易讲清楚价值的例子：

- XDP 包过滤：体现 KernelScript 如何描述高性能数据面逻辑
- TCP 拥塞控制：体现 KernelScript 如何描述 struct_ops 风格的内核扩展

## 第 1 页：为什么选这两个例子

- XDP 包过滤代表“高频、快速决策”的网络数据路径
- TCP 拥塞控制代表“协议行为可插拔”的内核控制逻辑
- 两者覆盖了 KernelScript 的两类典型目标：普通 eBPF 程序和 struct_ops 程序
- 放在一起讲，能清楚体现语言和编译器的表达范围

## 第 2 页：XDP 包过滤场景

- 场景目标：在网卡收包最早阶段快速判断是否放行
- 典型用途：基础 DDoS 防护、报文长度过滤、协议预筛选
- 关键价值：越早丢包，越少进入内核协议栈，系统开销越低
- 对编译器的要求：生成 verifier 友好、attach 简单、用户态加载流程清晰

## 第 3 页：XDP 例子在 KernelScript 里的表达

- 使用 `@xdp` 声明程序入口，语义直接对应 XDP 执行域
- 参数显式写成 `ctx: *xdp_md`，和内核上下文类型一致
- 返回值使用 `xdp_action`，直接表达 `XDP_PASS` / `XDP_DROP`
- 用户态 `main` 中通过 `load`、`attach`、`detach` 完成生命周期管理

可直接讲的代码要点：

- 先读取 `data` 和 `data_end`，计算报文大小
- 超过阈值就丢弃，否则放行
- 业务逻辑很短，但已经覆盖了“内核态处理 + 用户态加载”完整链路

## 第 4 页：XDP 例子的 PPT 总结句

- KernelScript 让 XDP 程序写法接近“带类型约束的策略描述”
- 既保留 eBPF 的执行语义，又减少手写 C 和样板代码负担
- 适合把简单过滤、早期拦截、包路径控制快速落地

## 第 5 页：TCP 拥塞控制场景

- 场景目标：把一组回调函数注册为 TCP 拥塞控制算法
- 典型用途：自定义拥塞窗口增长、状态切换处理、事件回调
- 和普通 XDP 程序不同，它不是“处理一个包”，而是“定义一类协议行为”
- 对编译器的要求：不仅要生成函数，还要生成可注册的 struct_ops 映射关系

## 第 6 页：TCP 拥塞控制在 KernelScript 里的表达

- 通过 `@struct_ops("tcp_congestion_ops")` 指定目标内核接口
- 使用 `impl minimal_congestion_control` 组织一组回调实现
- `ssthresh`、`cong_avoid`、`set_state`、`cwnd_event` 这些函数直接写在同一个实现块里
- 用户态 `main` 只需要 `register(minimal_congestion_control)` 即可完成注册

可直接讲的代码要点：

- `impl` 块的写法比手动构造结构体更直观
- 已实现的函数会成为 struct_ops 对应回调
- 未实现的可选函数可以留空，由生成结果处理为未绑定项
- 这种写法很适合讲“语言层直接建模内核扩展点”

## 第 7 页：TCP 拥塞控制例子的 PPT 总结句

- KernelScript 把 struct_ops 从“繁琐结构体装配”提升为“语义化接口实现”
- 对协议扩展类场景更友好，代码结构也更接近开发者思维模型
- 适合展示编译器不只会生成普通 eBPF 程序，也能覆盖内核可插拔机制

## 第 8 页：两个例子的对比页

| 维度 | XDP 包过滤 | TCP 拥塞控制 |
| --- | --- | --- |
| 关注点 | 单包快速决策 | 协议行为定义 |
| 执行模式 | 数据路径热点执行 | 内核协议栈回调 |
| 典型接口 | `@xdp fn ...` | `@struct_ops(...) impl ...` |
| 输出重点 | eBPF 程序 + attach 流程 | struct_ops 回调 + register 流程 |
| 适合展示的价值 | 性能路径、早期过滤、部署直观 | 语言抽象、内核扩展、接口建模 |

## 第 9 页：用这两个例子想传达什么

- KernelScript 不只是在“包装 eBPF C”
- 它是在更高层次上描述内核可编程能力
- 对简单数据路径程序，可以直接写成短小策略逻辑
- 对复杂协议扩展点，可以写成结构化接口实现
- 同一门语言覆盖从包处理到内核行为扩展的不同层次

## 第 10 页：演讲时可直接使用的收尾

- 如果说 XDP 例子说明 KernelScript 能高效表达“一个程序怎么处理包”
- 那么 TCP 拥塞控制例子说明它还能表达“一个内核子系统怎样被扩展”
- 两个例子放在一起，正好展示了 KernelScript 的广度、抽象能力和工程落地价值

## 对应示例文件

- XDP 包过滤示例：`examples/packet_filter.ks`
- TCP 拥塞控制示例：`examples/struct_ops_simple.ks`
- XDP 类型声明：`examples/xdp.kh`
- TCP struct_ops 声明：`examples/tcp_congestion_ops.kh`

## 对应 Mermaid 图

- XDP 包过滤流程图：`diagrams/xdp_packet_filter_flow.mmd`
- TCP 拥塞控制流程图：`diagrams/tcp_congestion_struct_ops_flow.mmd`