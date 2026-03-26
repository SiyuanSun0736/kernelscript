# KernelScript 编译器 6 页 PPT 文案版

## 第 1 页：KernelScript 编译器定位

- KernelScript 面向 eBPF 系统开发，不是通用语言编译器
- 一份 `.ks` 源码可以同时描述 eBPF、userspace、共享资源和可选 kfunc
- 编译器负责把同一份源码拆成多个目标产物
- 核心特点是“系统级编译”，而不是“单程序翻译”

## 第 2 页：整体流水线总览

- 前端负责解析源码、补齐依赖、建立语义约束
- 中端负责生成统一 IR，并分析多程序协同关系
- 后端负责分别生成 eBPF C、userspace C、kernel module C
- 整条流水线把 eBPF 领域规则前移到编译阶段处理

## 第 3 页：前端做什么

- 将 `.ks` 源码解析成 AST，完成词法与语法分析
- 展开 import / include，补齐头文件声明和模块依赖
- 建立符号表，统一管理函数、类型、map、config、global
- 执行类型检查、执行域检查和 builtin 语义检查
- 在进入 IR 前尽早拦截 verifier 常见风险

## 第 4 页：中端做什么

- 将 typed AST 降级成统一 IR，作为多后端共享中间层
- 把多个 eBPF 程序、userspace 逻辑和共享资源统一建模
- 分析控制流、循环、tail call、ring buffer 和 map 操作
- 做系统级资源规划和跨程序约束检查
- 为后端生成准备结构化、可消费的编译结果

## 第 5 页：后端做什么

- eBPF 后端生成 verifier 友好的 `.ebpf.c`
- userspace 后端生成 load、attach、detach、事件处理等协调逻辑
- kernel module 后端在存在 `@kfunc` 时生成 `.mod.c`
- 编译器最终输出的是完整工程产物，而不是单个目标文件

## 第 6 页：架构亮点与价值

- 前端把执行域、类型、安全问题尽量前置到编译期
- 中端以“多程序协同”而不是“单函数优化”为核心
- 后端一次编译生成 eBPF 工程所需的多类代码
- 相比手写 eBPF C + userspace 样板，KernelScript 把领域知识收编进编译器
