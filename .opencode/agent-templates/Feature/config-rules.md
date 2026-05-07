# 配置规则说明

本文件说明各 Agent 的配置规则和选择依据。

## 目录变量约定

所有过程文档使用统一的目录变量：

| 变量 | 说明 | 示例 |
|------|------|------|
| `${feature-name}` | 需求名称，用作目录名，英文小写字母，多个单词用 `-` 连接 | notification-group-management |

**重要约定**：
- 所有目录名都不包含时间戳，保持简洁便于引用
- `${feature-name}` 既是需求名称，也是目录名

**路径示例**：
- 文档目录：`.opencode/kb/features/notification-group-management/`
- 架构文档：`.opencode/kb/features/notification-group-management/feature-architecture.md`

---

## Temperature 配置规则

Temperature 控制 Agent 的创造性程度：

| 值 | 输出特点 | 适用场景 | 示例 |
|----|----------|----------|------|
| 0 | 严格遵守模板，输出确定性高，不偏离设计 | 严格执行、验证、总结 | 架构设计必须覆盖6维度，不能遗漏；验证必须严格执行标准 |
| 0.2 | 允许适度创造，但保持结构化，输出多样性提高 | 设计、规划、执行 | 开发设计可以灵活选择实现方案；任务执行可以创新解决技术问题 |

**配置依据**：

| Agent | Temperature | 原因 | 实际效果 |
|-------|-------------|------|----------|
| Feature-Agent | 0 | 主代理编排流程，需要严格按流程执行 | 状态管理确定性高，流程不偏离设计 |
| Architecture-SubAgent | 0 | 架构设计需要严格覆盖6维度 | 确保每个维度都有内容，不会遗漏关键设计点 |
| Dev-Design-SubAgent | 0.2 | 开发设计需要适度创造，生成代码示例 | 可以灵活选择实现方案，但必须包含完整的代码框架 |
| Plan-SubAgent | 0.2 | 任务分解需要适度创造，设计执行顺序 | 可以灵活划分任务粒度，但必须保持结构化输出 |
| Execute-SubAgent | 0.2 | 任务执行需要适度创造，解决技术问题 | 可以创新解决实现难点，但必须满足验收标准 |
| Verify-SubAgent | 0 | 独立验证需要严格执行验收标准 | 验证结论确定性高，不会放宽要求 |
| Doc-SubAgent | 0 | 总结文档需要严格按模板生成 | 文档结构完整，不会偏离模板要求 |

---

## Permission 配置规则

Permission 控制 Agent 的文件操作权限：

| 权限类型 | 值 | 适用场景 |
|----------|-----|----------|
| write | allow | 设计阶段生成文档，不需要用户确认 |
| write | ask | 执行阶段修改代码，需要用户确认每个修改 |
| edit | allow | 设计阶段修改文档，不需要用户确认 |
| edit | ask | 执行阶段修改代码，需要用户确认每个修改 |

**配置依据**：

| Agent | write | edit | 原因 |
|-------|-------|------|------|
| Feature-Agent | allow | allow | 主代理编排流程，生成状态文件和调用子代理，不修改业务代码 |
| Architecture-SubAgent | allow | allow | 架构设计阶段生成文档，需要灵活生成和修改架构文档 |
| Dev-Design-SubAgent | allow | allow | 开发设计阶段生成文档，需要灵活生成和修改设计文档 |
| Plan-SubAgent | ask | ask | 任务计划需要用户确认，避免自动生成不符合预期的计划 |
| Execute-SubAgent | ask | ask | 任务执行修改代码，必须用户确认每个修改，确保安全 |
| Verify-SubAgent | ask | ask | 验证阶段可能需要修改验证日志，需要用户确认 |
| Doc-SubAgent | ask | ask | 总结文档需要用户确认内容是否符合预期 |

---

## Tools 配置规则

各 Agent 的工具权限配置：

| Agent | bash | task | 原因 |
|-------|------|------|------|
| Feature-Agent | true | true | 主代理需要bash创建目录/重命名，需要task调用子代理 |
| Architecture-SubAgent | true | true | 架构子代理可能需要bash重命名目录，需要task调用explore |
| Dev-Design-SubAgent | false | true | 设计阶段不需要bash，需要task调用explore |
| Plan-SubAgent | false | true | 规划阶段不需要bash，需要task调用explore |
| Execute-SubAgent | true | true | 执行阶段需要bash运行测试命令，需要task调用verify |
| Verify-SubAgent | true | true | 验证阶段需要bash运行测试，需要task调用explore |
| Doc-SubAgent | false | true | 总结阶段不需要bash，需要task调用explore（如需） |

**bash权限限制**：

Feature-Agent 的 bash 权限仅限于以下编排型动作：
- 生成时间戳（YYYYMMDD-HHMMSS）
- 创建 `.opencode/kb/features/` 目录结构
- 重命名 feature 目录（从临时名改为正式名）
- 状态文件存在性检查
- 必要的文件系统操作（mkdir、mv、ls）

---

## Mode 配置规则

Agent 的运行模式：

| 值 | 适用场景 |
|----|----------|
| primary | 主代理，负责编排和决策 |
| subagent | 子代理，负责执行具体任务 |

**配置依据**：
- Feature-Agent：primary（主代理）
- 所有 SubAgent：subagent（子代理）

---

## 状态字段类型规则

状态文件中的字段类型约定：

| 字段 | 类型 | 说明 |
|------|------|------|
| `execute.tasks` | object | 任务字典，key为task_id，value为任务状态对象（**不能是array**） |
| `execute.waves` | array | Wave列表，每个wave包含完整状态信息 |
| `execute.dag` | object | 任务依赖关系图，key为task_id，value为依赖列表 |
| `wave.tasks` | array | Wave包含的任务ID列表（仅包含ID，**不包含任务详情**） |

**关键区分**：
- `execute.tasks` 是 object（字典），包含任务的完整状态
- `wave.tasks` 是 array（列表），仅包含任务ID

---

## 审批历史规则

approval_history 的追加规则：

| 阶段 | 是否追加 | 原因 |
|------|----------|------|
| Architecture | 是 | 架构师确认是关键决策点，需要记录 |
| Dev-Design | 是 | 开发人员确认是关键决策点，需要记录 |
| Plan | 是 | 用户确认任务计划是关键决策点，需要记录 |
| Execute | 否 | 任务执行不需要审批，由验证结果决定 |
| Doc | 否 | 总结阶段不需要审批 |

**追加时机**：
- 仅在用户明确批准后才追加
- 每次审批追加一条记录，不能覆盖旧记录
- 用于续跑和审计

---

## 调用子代理规则

Feature-Agent 调用子代理时的参数传递规则：

### 必传参数

所有子代理必须接收：
- `kb_dir`：文档存放目录
- `feature_dir`：当前目录名
- `feature_name`：当前需求名称（Architecture后已更新）

### 阶段特定参数

| 子代理 | 额外参数 | 说明 |
|--------|----------|------|
| Architecture | feature_requirement | 用户原始需求描述 |
| Dev-Design | feature_requirement, feature-architecture.md | 原始需求和架构文档 |
| Plan | feature-architecture.md, feature-dev-design.md | 架构和设计文档 |
| Execute | task_id, task_detail, files_write, files_read, feature-context.md | 任务详情和上下文 |
| Verify | task_id, files_changed, acceptance_criteria | 任务变更和验收标准 |
| Doc | feature-state.json | 全局状态和审批历史 |

---

## 目录重命名规则

Architecture 阶段完成后，目录重命名流程：

| 步骤 | 执行者 | 操作 |
|------|--------|------|
| 1. 生成需求名称 | Architecture-SubAgent | 分析架构文档，生成需求名称建议 |
| 2. 确认需求名称 | 用户 | 与架构师确认最终需求名称 |
| 3. 执行重命名 | Feature-Agent | 使用bash命令重命名目录 |
| 4. 更新状态文件 | Feature-Agent | 更新feature_dir、feature_name、kb_dir字段 |

**重命名时机**：
- 必须在用户批准 Architecture 后立即执行
- 重命名后再进入 Dev-Design 阶段

---

## Wave 定义规则

默认 Wave 定义：

| Wave | ID | 名称 | 目标 | 任务类型 |
|------|-----|------|------|----------|
| wave-1 | wave-1 | core_implementation | 核心功能实现 | core_implementation |
| wave-2 | wave-2 | extended_features | 扩展功能和配置 | extended_features |
| wave-3 | wave-3 | test_validation | 测试用例编写和验证 | test_validation |
| wave-4 | wave-4 | documentation | 文档更新和使用说明 | documentation |

**执行规则**：
- Wave 间默认串行推进
- Wave 内可在文件锁允许的前提下并行
- 未完成当前 wave，不得推进到下一 wave