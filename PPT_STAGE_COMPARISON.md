# KernelScript 前端 / 中端 / 后端对比表

这份表格适合放在 PPT 总览页，用来快速说明三段式架构的职责分工。

| 维度 | 前端 | 中端 | 后端 |
| --- | --- | --- | --- |
| 主要目标 | 把源码变成带语义约束的系统描述 | 把语义模型降级成统一 IR 并做系统级分析 | 把统一 IR 生成为多个可编译目标 |
| 输入 | `.ks` 源码、import、include、builtin 声明 | typed AST、多程序分析结果、符号信息 | IR、tail call 分析、ring buffer 分析、上下文信息 |
| 核心工作 | 解析、依赖补全、符号表、类型检查、安全检查 | lowering、控制流组织、资源分析、跨程序协调 | eBPF C 生成、userspace C 生成、kernel module C 生成 |
| 关注重点 | 语义正确、执行域合法、提前报错 | 多程序建模、资源规划、IR 组织 | 输出物正确、符合 verifier / libbpf / kfunc 约束 |
| 典型问题 | 函数能否在当前域调用、类型是否匹配、map 操作是否合法 | tail call 如何分配、共享资源如何建模、程序如何协同 | section 如何生成、attach 逻辑如何生成、是否需要额外模块 |
| 代表模块 | `lexer.mll`、`parser.mly`、`ast.ml`、`type_checker.ml`、`safety_checker.ml` | `ir.ml`、`ir_generator.ml`、`multi_program_analyzer.ml`、`tail_call_analyzer.ml` | `ebpf_c_codegen.ml`、`userspace_codegen.ml`、`kernel_module_codegen.ml` |
| 输出结果 | 带类型和语义约束的程序表示 | 可被多个后端消费的统一 IR | `.ebpf.c`、`.c`、`.mod.c`、可选测试与构建文件 |
| 一句话概括 | 负责“看懂源码” | 负责“组织系统” | 负责“产出代码” |

## 总览页可直接使用的总结句

- 前端回答“程序写得对不对”
- 中端回答“系统该怎么组织”
- 后端回答“最终代码怎么生成”
