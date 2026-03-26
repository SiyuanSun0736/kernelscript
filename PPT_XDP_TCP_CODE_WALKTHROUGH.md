# KernelScript PPT 讲解稿：从 XDP 包过滤到 TCP 拥塞控制

这份文档适合直接拆成 PPT 页面使用，重点不是泛泛介绍，而是结合真实代码讲清楚三件事：

- KernelScript 是怎么描述 eBPF/XDP 程序的
- KernelScript 是怎么描述 struct_ops/TCP 拥塞控制扩展的
- 编译器最终把这些高级写法降成了什么样的底层 C/eBPF 表达

---

## 第 1 页：为什么选这两个例子

这两个例子刚好覆盖 KernelScript 的两类能力：

- XDP 包过滤：说明它能写“高频数据路径上的快速决策程序”
- TCP 拥塞控制：说明它能写“协议栈中的可插拔行为扩展”

一句话总结：

> 一个例子展示“怎么处理包”，另一个例子展示“怎么扩展内核行为”。

演讲建议：

- 先用这一页告诉听众，后面不是讲两个孤立 demo，而是在展示同一门语言覆盖不同层级的内核可编程能力。

---

## 第 2 页：XDP 包过滤的业务场景

场景目标：

- 在网卡收包最早阶段判断一个包是否应该继续进入协议栈
- 如果包太大，直接丢弃
- 如果包正常，就继续放行

这个场景适合讲 XDP，因为：

- XDP 挂载点足够早
- 越早丢包，系统越省资源
- 逻辑非常短，适合第一次向听众解释 eBPF 程序模型

可以直接讲的业务规则：

- 包长大于 1500 字节，返回 `XDP_DROP`
- 否则返回 `XDP_PASS`

---

## 第 3 页：XDP 示例的 KernelScript 源码

代码来自 `examples/packet_filter.ks`：

```ks
include "xdp.kh"

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  var packet_size = ctx->data_end - ctx->data
  if (packet_size > 1500) {
    return XDP_DROP
  }
  return XDP_PASS
}
```

这一段最值得讲的点有 4 个：

1. `@xdp` 直接声明了这是一个 XDP 程序，而不是普通函数。
2. `ctx: *xdp_md` 明确说明它操作的是内核给 XDP 的上下文。
3. `ctx->data_end - ctx->data` 表示包数据区长度。
4. 返回值不是随便的整数，而是类型化的 `xdp_action`。

可以现场口述的解释：

- 这里没有让用户手写 `SEC("xdp")`、函数属性、底层类型转换。
- 写法更像“描述规则”，而不是“拼装 C 模板”。

---

## 第 4 页：XDP 示例的用户态生命周期

同一个文件里还有用户态主函数：

```ks
fn main() -> i32 {
  var prog = load(packet_filter)
  attach(prog, "eth0", 0)

  print("Packet filter attached to eth0")
  print("Filtering incoming packets...")

  detach(prog)
  print("Packet filter detached")

  return 0
}
```

这一页要传达的是：

- KernelScript 不只描述 eBPF 程序本体
- 它还把加载、挂载、卸载这些用户态动作放进统一语言里

这里可以强调的流程：

1. `load(packet_filter)` 加载编译后的 eBPF 程序
2. `attach(prog, "eth0", 0)` 把程序挂到网卡
3. `detach(prog)` 演示程序卸载

PPT 讲解句：

> 对使用者来说，这不是“再写一套 libbpf 用户态代码”，而是“在同一份源码里描述整个程序生命周期”。

---

## 第 5 页：XDP 示例编译后变成什么

生成的 eBPF C 在 `examples/packet_filter/packet_filter.ebpf.c` 中，核心片段如下：

```c
SEC("xdp")
enum xdp_action packet_filter(struct xdp_md* ctx) {
    __u8* __arrow_access_0;
    __u8* __arrow_access_1;
    __u64 __binop_2;
    __u8 __binop_3;

    __arrow_access_0 = (void*)(long)ctx->data_end;
    __arrow_access_1 = (void*)(long)ctx->data;
    __binop_2 = (((__u64)__arrow_access_0) - ((__u64)__arrow_access_1));
    __u64 packet_size = __binop_2;
    __binop_3 = (packet_size > 1500);
    if (__binop_3) {
        return XDP_DROP;
    }
    return XDP_PASS;
}
```

这一页建议重点讲“降级”过程：

- `@xdp` 被编译成 `SEC("xdp")`
- `ctx->data_end` 和 `ctx->data` 被翻译成底层指针访问
- 高层变量 `packet_size` 仍然保留了较好的可读性
- 判断逻辑最终变成 verifier 可接受的 C 代码

一句话总结：

> KernelScript 做的不是隐藏底层，而是把底层细节系统化地生成出来。

---

## 第 6 页：从 XDP 例子里想传达的价值

这一页不讲新代码，只讲结论：

- 代码短，但覆盖了“内核态逻辑 + 用户态加载”完整链路
- 语义比手写 eBPF C 更直观
- 输出仍然是标准 eBPF/libbpf 路线，方便落地

适合 PPT 的一句话：

> 用更高层的语言描述规则，但不脱离现有 eBPF 工程生态。

---

## 第 7 页：TCP 拥塞控制的业务场景

第二个例子切换到 TCP 拥塞控制。

这个场景和 XDP 最大的不同是：

- XDP 是“一个包来了，我怎么处理”
- TCP 拥塞控制是“TCP 协议运行时，我定义它的行为回调”

为什么这个例子很重要：

- 它不是普通程序入口
- 它依赖内核定义的 `struct tcp_congestion_ops`
- 它体现 KernelScript 可以描述 struct_ops 这种更高级的内核扩展接口

---

## 第 8 页：TCP 拥塞控制的 KernelScript 源码

代码来自 `examples/struct_ops_simple.ks`：

```ks
include "tcp_congestion_ops.kh"

@struct_ops("tcp_congestion_ops")
impl minimal_congestion_control {
    fn ssthresh(sk: *u8) -> u32 {
        return 16
    }

    fn cong_avoid(sk: *u8, ack: u32, acked: u32) -> void {
    }

    fn set_state(sk: *u8, new_state: u8) -> void {
    }

    fn cwnd_event(sk: *u8, ev: u32) -> void {
    }
}
```

这一页建议从“语言抽象”角度讲：

1. `@struct_ops("tcp_congestion_ops")` 指明目标内核接口。
2. `impl minimal_congestion_control` 表示“我要提供这一组回调实现”。
3. 每个 `fn` 对应 `tcp_congestion_ops` 里的一个函数槽位。
4. 开发者不需要手写一个巨大的结构体初始化过程。

适合现场讲的一句：

> 以前是围绕结构体字段来思考，现在是围绕接口实现来思考。

---

## 第 9 页：TCP 例子的注册流程

同一个文件里的用户态主函数：

```ks
fn main() -> i32 {
    var result = register(minimal_congestion_control)
    return result
}
```

这里可以强调两点：

- 用户态不再显式拼接复杂注册细节
- 语言层已经知道 `minimal_congestion_control` 是一个 struct_ops 实现块

PPT 讲解句：

> XDP 例子展示的是 attach 一个程序，TCP 拥塞控制例子展示的是 register 一组内核行为。

---

## 第 10 页：TCP 示例编译后变成什么

生成的 eBPF C 在 `examples/struct_ops_simple/struct_ops_simple.ebpf.c` 中，核心片段如下：

```c
SEC("struct_ops/ssthresh")
__u32 ssthresh(__u8* sk) {
    return 16;
}

SEC("struct_ops/cong_avoid")
void cong_avoid(__u8* sk, __u32 ack, __u32 acked) {
}

SEC(".struct_ops")
struct tcp_congestion_ops minimal_congestion_control = {
    .ssthresh = (void *)ssthresh,
    .cong_avoid = (void *)cong_avoid,
    .set_state = (void *)set_state,
    .cwnd_event = (void *)cwnd_event,
};
```

这一页要解释清楚两个层次：

- 每个回调函数先被编译成对应的 `SEC("struct_ops/...")` 函数
- 然后再自动汇总成一个 `.struct_ops` 实例

听众通常会在这里理解到：

- `impl` 不是语法糖而已
- 它背后对应的是一整套真实的 struct_ops 目标代码生成

---

## 第 11 页：为什么 `impl` 写法更适合讲 struct_ops

如果让开发者直接面对底层表示，他要关心的是：

- 结构体有哪些字段
- 哪些字段是函数指针
- 哪些字段要绑定，哪些字段可以留空
- 最终如何组成一个可注册对象

而在 KernelScript 里，他关心的是：

- 我要实现哪些回调
- 每个回调的签名是什么
- 注册哪个实现块

这一页适合下结论：

> KernelScript 把 struct_ops 从“结构体装配问题”提升成了“接口实现问题”。

---

## 第 12 页：XDP 与 TCP 拥塞控制的对比

| 维度 | XDP 包过滤 | TCP 拥塞控制 |
| --- | --- | --- |
| 本质 | 单个程序入口 | 一组回调接口 |
| 触发方式 | 包到达时执行 | TCP 协议栈事件触发 |
| KernelScript 抽象 | `@xdp fn` | `@struct_ops ... impl` |
| 用户态动作 | `load + attach + detach` | `register` |
| 编译结果重点 | `SEC("xdp")` 程序 | `SEC("struct_ops/... ") + .struct_ops` |
| 最适合展示的价值 | 高性能数据路径 | 内核行为扩展 |

这页的目标是让听众看到：

- 同一门语言在抽象层面是统一的
- 但针对不同内核机制，又能提供很贴合场景的表达方式

---

## 第 13 页：用这两个例子证明了什么

可以把最后的观点收束成 4 句话：

1. KernelScript 能描述传统 eBPF 程序，例如 XDP 包过滤。
2. KernelScript 也能描述更复杂的内核扩展接口，例如 TCP struct_ops。
3. 它在源码层强调“语义表达”，在输出层仍然对接标准 eBPF/libbpf 生态。
4. 所以它不是脱离工程现实的新语法，而是对现有内核可编程能力的一层更高质量抽象。

适合作为收尾的一句话：

> XDP 例子说明它能写程序，TCP 拥塞控制例子说明它能写接口；两者合起来，说明它能组织一套完整的内核可编程开发模型。

---

## 附：做 PPT 时建议引用的源码位置

- XDP 源码：`examples/packet_filter.ks`
- XDP 生成代码：`examples/packet_filter/packet_filter.ebpf.c`
- XDP 用户态加载器：`examples/packet_filter/packet_filter.c`
- TCP struct_ops 源码：`examples/struct_ops_simple.ks`
- TCP struct_ops 生成代码：`examples/struct_ops_simple/struct_ops_simple.ebpf.c`
- TCP 用户态加载器：`examples/struct_ops_simple/struct_ops_simple.c`

## 附：PPT 制作建议

- 如果页数紧张，可以保留第 1、3、5、8、10、12、13 页。
- 如果你想强调“编译器能力”，就重点展示第 5 页和第 10 页。
- 如果你想强调“语言设计”，就重点展示第 3 页和第 8 页。
- 如果你想强调“工程落地”，就把第 4 页、第 9 页和生成代码页放在一起讲。