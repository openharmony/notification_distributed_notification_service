# 子代理完成通知模板

本文件包含各 SubAgent 完成后的通知模板。

**重要约定**：所有过程文档存放在 `.opencode/kb/features/${feature-name}/` 目录下，其中 `${feature-name}` 为需求名称。

## 1. Architecture SubAgent 完成通知模板

```text
[ARCHITECTURE-COMPLETE] Architecture 子代理已完成架构设计:
- 需求名称: <feature_name>
- 输出文件: .opencode/kb/features/${feature-name}/feature-architecture.md
- 包含维度:
  ✅ 1. 需求背景与价值 - 使用场景、业务价值、优先级依据
  ✅ 2. 上下游与边界 - 依赖方、影响方、明确边界
  ✅ 3. 功能细节 - 业务流程、数据流向、接口定义
  ✅ 4. 实现方案 - 技术方案、性能要求、容错处理
  ✅ 5. 约束与要求 - 权限控制、参数校验、埋点打点、兼容性
  ✅ 6. 测试策略 - 测试场景、验证方法、测试数据

架构设计要点:
- 技术方案: <简要说明选择的技术方案>
- 核心接口: <列出主要新增接口>
- 关键约束: <列出主要约束条件>
- 测试覆盖: <说明测试策略>

下一步: 等待 Feature-Agent 向用户展示并请求确认
```

---

## 2. Dev-Design SubAgent 完成通知模板

```text
[DEV-DESIGN-COMPLETE] Dev-Design 子代理已完成:
- 开发设计方案: .opencode/kb/features/${feature-name}/feature-dev-design.md
- 需求上下文: .opencode/kb/features/${feature-name}/feature-context.md
- 包含: 开发概述、开发架构设计、详细开发设计、开发流程设计、接口定义、开发测试策略

开发设计要点:
- 新增模块数: <N> 个 (列出模块名称)
- 扩展接口数: <N> 个 (列出接口名称)
- 核心类: <列出主要新增类>
- 实现路径: <简要说明实现步骤>

下一步: 等待开发人员确认批准
```

---

## 3. Plan SubAgent 完成通知模板

```text
[PLAN-COMPLETE] Plan 子代理已完成:
- 任务计划: .opencode/kb/features/${feature-name}/feature-plan.md
- 总任务数: <N>
- Wave 数: 4
- 测试用例数: <N>
- 文档更新数: <N>

任务分解要点:
- Wave 1 (核心实现): <N> 个任务
- Wave 2 (扩展功能): <N> 个任务
- Wave 3 (测试验证): <N> 个任务
- Wave 4 (文档完善): <N> 个任务
- 高风险任务: <列出>

下一步: 等待用户确认批准
```

---

## 4. Execute SubAgent 完成通知模板

```text
[EXECUTE-COMPLETE] Execute 子代理已完成:
- 任务ID: <task_id>
- 任务名称: <task_name>
- 任务类型: <task_type>
- Wave: <wave_id>
- 输出文件: .opencode/kb/features/${feature-name}/feature-<task-name>.md
- 已移交: Verify 子代理
- 验证结果: <通过/失败>

任务执行要点:
- 实际修改文件数: <N>
- 新增测试用例数: <N>
- 验收标准满足: <全部/部分>

下一步: 等待 Feature-Agent 调用下一个任务或进入总结阶段
```

---

## 5. Verify SubAgent 完成通知模板

```text
[VERIFY-COMPLETE] Verify 子代理已完成:
- 任务ID: <task_id>
- 任务名称: <task_name>
- 验证结果: <通过/失败>
- 验证日志: .opencode/kb/features/${feature-name}/verify-log.md

验证要点:
- 变更范围审计: <通过/失败>
- 编译验证: <通过/失败>
- 测试验证: <通过/失败>
- 验收标准验证: <通过/失败>
- 代码质量验证: <通过/失败>
- 接口兼容性验证: <通过/失败>
- 测试覆盖验证: <通过/失败>

下一步: 
- 若通过: 返回 Execute 子代理进入任务总结
- 若失败: 返回 Execute 子代理进行修复
```

---

## 6. Doc SubAgent 完成通知模板

```text
[DOC-COMPLETE] Doc 子代理已完成:
- 功能总结: .opencode/kb/features/${feature-name}/${feature-name}.md
- 测试报告: .opencode/kb/features/${feature-name}/feature-test-report.md
- 包含完整的功能说明、架构图、测试覆盖、审批历史

文档要点:
- 功能实现完整性: <简要说明>
- 测试覆盖率: <百分比>
- 验收标准满足情况: <说明>
- 遗留问题: <列出>

需求实现流程已完成。

所有文档位置:
- .opencode/kb/features/${feature-name}/${feature-name}.md (功能总结)
- .opencode/kb/features/${feature-name}/feature-test-report.md (测试报告)
- .opencode/kb/features/${feature-name}/feature-architecture.md (架构设计)
- .opencode/kb/features/${feature-name}/feature-dev-design.md (开发设计方案)
- .opencode/kb/features/${feature-name}/feature-plan.md (任务计划)
- .opencode/kb/features/${feature-name}/verify-log.md (验证日志)
```