# 执行模板

本文件包含 Feature-Execute-SubAgent 使用的执行阶段模板。

**重要约定**：所有过程文档存放在 `.opencode/kb/features/${feature-name}/` 目录下，其中 `${feature-name}` 为需求名称。

## 1. 执行前确认模板

```text
[EXECUTE-CONFIRM] 准备执行任务:
- 任务ID: <task_id>
- 任务类型: <task_type>
- Wave: <wave_id>
- 可写文件: <files_write列表>
- 只读文件: <files_read列表>
- 验收标准: <acceptance_criteria列表>

是否继续执行?[继续/停止]
```

---

## 2. 任务阻塞输出模板

```text
[EXECUTE-BLOCKED] 任务执行被阻塞:
- 原因: <原因说明>
- 任务ID: <task_id>
- 问题: <具体问题>

请等待 Feature-Agent 决策。
```

---

## 3. 任务失败达到最大重试次数模板

```text
[EXECUTE-FAILED] 任务执行失败,已达到最大重试次数:
- 任务ID: <task_id>
- 重试次数: 3
- 最后失败原因: <原因>

需要人工介入处理。
```

---

## 4. 任务完成后输出模板

```text
[EXECUTE-COMPLETE] 任务执行完成:
- 任务ID: <task_id>
- 任务名称: <task_name>
- 任务类型: <task_type>
- Wave: <wave_id>
- 实际修改文件: <files_changed列表>
- 验收标准验证: <全部通过/部分通过>
- 已移交 Verify 子代理验证

任务总结文档: .opencode/kb/features/${feature-name}/feature-<task-name>.md

**执行摘要**:
- 新增代码行数: <N>
- 修改代码行数: <M>
- 新增文件数: <N>
- 修改文件数: <M>
- 新增测试用例: <N>

**关键实现**:
- <简要说明关键实现点1>
- <简要说明关键实现点2>
```

---

## 5. 任务失败输出模板

```text
[EXECUTE-FAILED] 任务执行失败:
- 任务ID: <task_id>
- 任务类型: <task_type>
- Wave: <wave_id>
- 失败原因: <失败类型>
- 失败详情: <详细错误信息>
- 当前重试次数: <retry_count>
- 需要的操作: <修复/重试/人工介入>

错误信息:
- <具体错误信息>
```

---

## 6. 状态汇报说明

Execute 子代理在完成任务后，必须向主代理汇报以下信息，供主代理更新状态文件：

### 任务完成时汇报

```json
{
  "task_id": "<task_id>",
  "task_name": "<task_name>",
  "status": "done",
  "files_changed": ["<实际修改文件列表>"],
  "verified": true,
  "completed_at": "<ISO时间戳>",
  "task_summary": ".opencode/kb/features/${feature-name}/feature-<task-name>.md",
  "execution_details": {
    "new_files": <N>,
    "modified_files": <M>,
    "new_lines": <N>,
    "modified_lines": <M>,
    "new_tests": <N>
  }
}
```

### 任务失败时汇报

```json
{
  "task_id": "<task_id>",
  "task_name": "<task_name>",
  "status": "failed",
  "retry_count": "<当前值>",
  "last_error": "<失败类型>: <详细错误信息>",
  "needs_retry": true/false,
  "completed_at": "<ISO时间戳>",
  "failure_details": {
    "error_type": "<OUT_OF_SCOPE/COMPILE_ERROR/TEST_FAILURE/ACCEPTANCE_NOT_MET/QUALITY_VIOLATION>",
    "error_message": "<详细错误信息>",
    "files_involved": ["<相关文件列表>"],
    "suggested_fix": "<建议修复方案>"
  }
}
```

**注意**：Execute 子代理**不直接更新状态文件**，只向主代理汇报结果，由主代理统一维护状态。