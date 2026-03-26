# KernelScript 编译器三段式要点

这份文档面向 PPT 提炼，重点不是展开细节，而是快速说明 KernelScript 编译器的前端、中端、后端分别在做什么、为什么重要。

## 一页总览

KernelScript 编译器不是传统的“单程序 -> 单目标”流水线，而是把同一份 `.ks` 源码拆成多个目标产物：

- 前端：把源码变成可分析的语义模型
- 中端：把多程序系统降级成统一 IR，并做约束分析与资源规划
- 后端：分别生成 eBPF C、userspace C、可选 kernel module C

## 前端要点

### 1. 前端的核心职责

- 把 `.ks` 源码解析成 AST
- 展开 import / include，补齐编译单元依赖
- 建立符号表，形成全局语义视图
- 做类型检查和执行域检查
- 在进入 IR 前尽早拦截 eBPF 常见错误

### 2. 前端处理的关键问题

- 语法是否合法
- 一个函数属于哪个执行域：eBPF、userspace、kfunc、test
- map、config、global、struct、enum 等顶层声明如何进入统一语义环境
- `load`、`attach`、`detach` 等 builtin 是否出现在合法上下文
- `match`、`try/catch`、`new/delete` 等高级语法是否满足类型和语义约束

### 3. 前端的关键模块

- `lexer.mll`：词法分析
- `parser.mly`：语法分析
- `parse.ml`：统一解析入口
- `ast.ml`：核心抽象语法树定义
- `import_resolver.ml`：处理 `.ks` / `.py` 导入
- `include_resolver.ml`：处理 `.kh` 声明展开
- `symbol_table.ml`：构建全局符号表
- `type_checker.ml`：类型检查与执行域规则检查
- `safety_checker.ml`：前置安全检查

### 4. 前端的 PPT 关键词

- 源码理解
- 语义建模
- 依赖补全
- 类型与安全前置检查
- eBPF 约束提前暴露

### 5. 前端一句话总结

前端负责把“文本形式的 KernelScript 程序”变成“带完整语义约束的系统描述”。

## 中端要点

### 1. 中端的核心职责

- 把 typed AST 降级成统一 IR
- 统一表达 userspace、多个 eBPF 程序和共享资源
- 分析跨程序关系，而不是只看单函数
- 为后端代码生成准备结构化中间结果

### 2. 中端最重要的设计点

- IR 的建模对象是“多程序系统”，不是单个函数
- 同一编译单元里可以同时含有多个 eBPF 程序、userspace 逻辑、共享 map、ring buffer 信息
- 中端更关注正确性、资源规划、调用模式，而不是传统算术优化

### 3. 中端处理的关键问题

- AST 到 IR 的 lowering
- 控制流与基本块构建
- map 操作降级
- loop 分析
- tail call 检测与索引分配
- ring buffer 注册和分析
- 函数签名一致性验证
- 多程序协同的资源与约束检查

### 4. 中端的关键模块

- `ir.ml`：中间表示定义
- `ir_generator.ml`：typed AST 到 IR 的降级
- `multi_program_analyzer.ml`：多程序系统分析
- `multi_program_ir_optimizer.ml`：系统级 IR 编排与优化
- `ir_analysis.ml`：通用 IR 分析
- `loop_analysis.ml`：循环分析
- `tail_call_analyzer.ml`：tail call 分析
- `map_assignment.ml` / `map_operations.ml`：map 相关语义处理
- `ir_function_system.ml`：函数签名验证

### 5. 中端的 PPT 关键词

- IR 降级
- 多程序建模
- 系统级分析
- 资源规划
- tail call / ring buffer 协调

### 6. 中端一句话总结

中端负责把前端得到的语义模型组织成“可跨后端复用的系统级 IR”，并完成多程序协同分析。

## 后端要点

### 1. 后端的核心职责

- 把统一 IR 分别翻译成不同目标代码
- 面向不同运行域输出不同产物
- 保证生成结果既符合语言语义，也符合 eBPF 生态约束

### 2. 后端的主要输出物

- `.ebpf.c`：eBPF 程序 C 代码
- `.c`：userspace 协调程序 C 代码
- `.mod.c`：可选的内核模块 C 代码
- `.test.c`：测试模式输出
- `Makefile`：可选构建脚本

### 3. 后端的关键子方向

#### eBPF 后端

- 生成 `SEC("...")` section
- 生成 map 定义
- 生成 helper 调用
- 把 IR 控制流还原成 verifier 友好的 C
- 处理 dynptr、ring buffer、tail call 等 eBPF 语义

#### userspace 后端

- 生成程序加载与 attach/detach 逻辑
- 生成 map 和 ring buffer 协调代码
- 生成事件分发和运行时管理逻辑
- 处理 Python bridge 和模块协作

#### kernel module 后端

- 为 `@kfunc` 生成内核模块代码
- 生成导出函数实现与注册逻辑
- 补齐内核模块样板

### 4. 后端的关键模块

- `ebpf_c_codegen.ml`：eBPF C 代码生成
- `userspace_codegen.ml`：userspace C 代码生成
- `kernel_module_codegen.ml`：kernel module C 代码生成
- `context/`：按 XDP、TC、tracepoint、probe 等上下文拆分的专用 codegen

### 5. 后端的 PPT 关键词

- 多目标生成
- eBPF C 输出
- userspace 协调程序
- kfunc 内核模块
- 面向 verifier 的代码生成

### 6. 后端一句话总结

后端负责把统一 IR 拆解成 eBPF、userspace、kernel module 等多个实际可编译的目标产物。

## 适合放进 PPT 的结论

### 1. 与传统编译器的差异

- 不是单程序编译器，而是系统级编译器
- 不是单一目标输出，而是多目标协同生成
- 不只做语法翻译，还把 eBPF 领域规则收编进编译器

### 2. 最值得强调的三个亮点

- 前端提前做执行域、类型和安全约束检查
- 中端以“多 eBPF 程序 + userspace 协同”为核心建模对象
- 后端一次编译生成完整 eBPF 工程所需的多类代码

### 3. 一句话总总结

KernelScript 的编译器本质上是一个面向 eBPF 系统开发的多目标编译流水线：前端做语义收敛，中端做系统级 IR 与分析，后端做多目标代码生成。