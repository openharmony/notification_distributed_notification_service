# KB (Knowledge Base) - 知识库目录说明

## 概述

本目录用于存放所有AI辅助开发流程的过程文档和知识资产。

## 目录结构

```text
.opencode/kb/
├── features/                  # 所有需求实现的过程文档
│   ├── 20260506-103800-notification-group-management/
│   ├── 20260506-141500-batch-publish-api/
│   └── ...
└── README.md                  # 本说明文档
```

## features 目录说明

`features/` 目录用于存放所有需求实现（Feature Agent）的过程文档。

### 目录命名规则

每个 feature 目录的命名格式：`${time}-${feature-name}`

其中：
- **`${time}`**：启动时间戳，格式 YYYYMMDD-HHMMSS（如 20260506-103800）
- **`${feature-name}`**：需求名称，英文小写字母，多个单词用 `-` 连接

**命名示例**：
- `20260506-103800-notification-group-management`
- `20260506-141500-batch-publish-api`
- `20260507-091500-custom-notification-filter`

### 单个 feature 目录内容

每个 feature 目录包含以下文件：

```text
${time}-${feature-name}/
├── feature-state.json        # 全局状态（机器可读）
├── feature-scope.md          # Phase 1: 需求范围与相关模块
├── feature-context.md        # Phase 1: 上下文与验收标准
├── feature-dev-design.md           # Phase 2: 已批准的开发设计方案
├── feature-plan.md           # Phase 3: 已批准的任务计划
├── feature-<task-name>.md    # Phase 4: 单任务总结（多个）
├── verify-log.md             # Phase 4: 逐任务验证日志
├── feature-test-report.md    # Phase 5: 测试报告
└── ${feature-name}.md        # Phase 5: 最终总结文档
```

### 文件说明

| 文件 | 阶段 | 说明 |
|------|------|------|
| `feature-state.json` | 全局 | 流程状态，支持断点续跑 |
| `feature-scope.md` | SCOPE | 需求理解、模块识别、架构快照 |
| `feature-context.md` | SCOPE | 验收标准、上下文信息 |
| `feature-dev-design.md` | DEV-DESIGN | 开发设计方案、架构图、接口定义 |
| `feature-plan.md` | PLAN | 任务分解、DAG、Wave、测试计划 |
| `feature-*.md` | EXECUTE | 单任务实现总结（多个） |
| `verify-log.md` | EXECUTE | 验证日志，包含所有任务验证记录 |
| `feature-test-report.md` | DOC | 测试覆盖报告 |
| `${feature-name}.md` | DOC | 功能总结文档，包含架构图和使用说明 |

## 设计目的

1. **过程可追溯**：所有决策和实现过程都有完整记录
2. **断点续跑**：状态文件支持流程中断后继续执行
3. **审计友好**：审批历史和验证日志便于审计
4. **知识沉淀**：设计文档和总结文档形成知识资产
5. **集中管理**：所有过程文档统一存放，便于查找和管理

## 使用方式

1. **Feature Agent 自动创建**：启动需求实现流程时，Agent 自动创建对应目录
2. **手动查看**：可通过文件浏览器或命令行查看过程文档
3. **断点续跑**：向 Agent 提供已有 feature 目录路径，可从中断处继续

## 示例：查看 feature 目录

```bash
# 列出所有 feature
ls -la .opencode/kb/features/

# 查看特定 feature 的文档
ls -la .opencode/kb/features/20260506-103800-notification-group-management/

# 查看状态文件
cat .opencode/kb/features/20260506-103800-notification-group-management/feature-state.json
```

## 未来扩展

kb 目录未来可能扩展其他类型的知识资产：

```text
.opencode/kb/
├── features/          # 需求实现过程文档
├── refactors/         # 重构过程文档（未来）
├── bugs/              # Bug修复过程文档（未来）
├── learnings/         # 学习总结和最佳实践（未来）
└── README.md          # 本说明文档
```