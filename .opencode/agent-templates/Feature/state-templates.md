# 状态文件模板

本文件包含 Feature-Agent 使用的状态文件相关模板。

**重要约定**：
- 所有过程文档存放在 `.opencode/kb/features/${feature-name}/` 目录下
- `${feature-name}`：需求名称，用作目录名，英文小写字母，多个单词用 `-` 连接

## 1. 状态文件结构模板

使用以下结构维护需求实现全局状态：

```json
{
  "feature_name": "<需求名称>",
  "kb_dir": ".opencode/kb/features/<需求名称>",
  "feature_requirement": "<用户提供的原始需求描述>",
  "entry_points": [],
  "excludes": [],
  "acceptance_criteria": [],
  "created_at": "<ISO时间戳>",
  "current_phase": "architecture",
  "approval_history": [],
  "phases": {
    "architecture": {
      "status": "pending",
      "outputs": [
        ".opencode/kb/features/${feature-name}/feature-architecture.md"
      ],
      "user_interactions_done": false
    },
    "dev_design": {
      "status": "pending",
      "outputs": [
        ".opencode/kb/features/${feature-name}/feature-dev-design.md",
        ".opencode/kb/features/${feature-name}/feature-context.md"
      ],
      "approval": {
        "status": "pending",
        "approved_at": null,
        "summary": null
      }
    },
    "plan": {
      "status": "pending",
      "output": ".opencode/kb/features/${feature-name}/feature-plan.md",
      "approval": {
        "status": "pending",
        "approved_at": null,
        "summary": null
      }
    },
    "execute": {
      "status": "blocked",
      "blocked_by": ["dev_design_approval", "plan_approval"],
      "current_wave": null,
      "current_task": null,
      "waves": [],
      "dag": {},
      "tasks": {},
      "file_locks": [],
      "updated_at": null
    },
    "doc": {
      "status": "pending",
      "outputs": [
        ".opencode/kb/features/${feature-name}/${feature-name}.md",
        ".opencode/kb/features/${feature-name}/feature-test-report.md"
      ]
    }
  },
  "test_coverage": {
    "unit_tests": [],
    "functional_tests": [],
    "performance_tests": [],
    "coverage_target": "90%"
  },
  "verify_log": ".opencode/kb/features/${feature-name}/verify-log.md"
}
```

**字段说明**:
- `feature_name`：需求名称，用作目录名，由 Architecture 子代理分析后生成或用户指定
- `kb_dir`：完整知识库路径 `.opencode/kb/features/${feature-name}`
- `feature_requirement`：用户提供的原始需求描述
- `phases.architecture.user_interactions_done`：标记 Architecture 阶段的用户交互是否完成
- `execute.tasks`：任务字典（object格式），key为task_id，value为任务状态对象
- `execute.dag`：任务依赖关系图（object格式），key为task_id，value为依赖列表

**execute 阶段字段说明**:

| 字段 | 类型 | 说明 |
|------|------|------|
| `execute.status` | string | execute 阶段整体状态：blocked / pending / running / done |
| `execute.blocked_by` | array | 阻塞原因列表：dev_design_approval / plan_approval |
| `execute.current_wave` | string | 当前正在执行的 wave ID |
| `execute.current_task` | string | 当前正在执行的任务 ID |
| `execute.waves` | array | Wave 列表，每个 wave 包含完整状态信息 |
| `execute.dag` | object | 任务依赖关系图，key为task_id，value为依赖列表 |
| `execute.tasks` | object | 任务字典，key为任务 ID，value为任务状态对象（必须是object格式，不能是array） |
| `execute.file_locks` | array | 文件锁列表，记录被锁定的文件和锁定者 |
| `execute.updated_at` | string | execute 阶段状态最后更新时间（ISO 时间戳） |

**wave 状态字段说明**:

每个 wave 对象包含以下字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | Wave 唯一标识（如 wave-1） |
| `name` | string | Wave 名称（如 core_implementation） |
| `tasks` | array | Wave 包含的任务 ID 列表（仅包含ID，不包含任务详情） |
| `status` | string | Wave 状态：pending / running / done |
| `completed_tasks` | array | Wave 中已完成的任务 ID 列表 |
| `started_at` | string | Wave 开始时间（ISO 时间戳） |
| `completed_at` | string | Wave 完成时间（ISO 时间戳） |

**注意**：`wave.tasks` 是任务ID列表（array），而 `execute.tasks` 是任务字典（object），两者含义不同。

**task 状态字段说明**:

每个任务对象包含以下字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 任务唯一标识（如 T001） |
| `name` | string | 任务名称 |
| `wave_id` | string | 所属 wave ID |
| `type` | string | 任务类型：core_implementation / extended_features / test_validation / documentation |
| `depends` | array | 依赖的任务 ID 列表 |
| `files_write` | array | 可写文件路径列表 |
| `files_read` | array | 只读文件路径列表 |
| `acceptance_criteria` | array | 验收标准列表 |
| `test_commands` | array | 测试命令列表 |
| `evidence_required` | array | 需要的证据产物列表 |
| `risk_level` | string | 风险等级：low / medium / high |
| `description` | string | 任务描述 |
| `status` | string | 任务状态：pending / running / done / failed / human_review |
| `retry_count` | integer | 当前重试次数（0-3） |
| `last_error` | string | 最后一次失败的错误信息 |
| `verified` | boolean | 是否已通过 Verify 子代理验证 |
| `started_at` | string | 任务开始时间（ISO 时间戳） |
| `completed_at` | string | 任务完成时间（ISO 时间戳） |
| `files_locked` | array | 当前锁定的文件路径列表 |

**file_locks 字段说明**:

每个文件锁对象包含以下字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `file` | string | 被锁定的文件路径（相对于工作区根目录） |
| `locked_by` | string | 锁定该文件的任务 ID |
| `locked_at` | string | 锁定时间（ISO 时间戳） |

---

## 2. 审批历史记录模板

`approval_history` 采用追加写入,单条记录结构如下:

```json
{
  "phase": "architecture | dev_design | plan",
  "decision": "approved | rejected | revised",
  "approved_by": "user",
  "approved_at": "<ISO时间戳>",
  "summary": "<用户确认摘要>",
  "document": "<对应阶段的产物文档路径>"
}
```

**示例**：

```json
[
  {
    "phase": "architecture",
    "decision": "approved",
    "approved_by": "user",
    "approved_at": "2026-05-06T10:45:00Z",
    "summary": "架构设计文档已确认，需求名称确定为 notification-group-management",
    "document": ".opencode/kb/features/notification-group-management/feature-architecture.md"
  },
  {
    "phase": "dev_design",
    "decision": "approved",
    "approved_by": "user",
    "approved_at": "2026-05-06T11:30:00Z",
    "summary": "开发设计方案已确认，可以开始任务分解",
    "document": ".opencode/kb/features/notification-group-management/feature-dev-design.md"
  },
  {
    "phase": "plan",
    "decision": "approved",
    "approved_by": "user",
    "approved_at": "2026-05-06T12:00:00Z",
    "summary": "任务计划已确认，共11个任务，按4个wave执行",
    "document": ".opencode/kb/features/notification-group-management/feature-plan.md"
  }
]
```

---

## 3. 运行时状态示例

以下是 Execute 阶段运行时的状态文件示例：

```json
{
  "execute": {
    "status": "running",
    "blocked_by": [],
    "current_wave": "wave-1",
    "current_task": "T002",
    "waves": [
      {
        "id": "wave-1",
        "name": "core_implementation",
        "tasks": ["T001", "T002", "T003"],
        "status": "running",
        "completed_tasks": ["T001"],
        "started_at": "2026-05-06T10:38:00Z",
        "completed_at": null
      },
      {
        "id": "wave-2",
        "name": "extended_features",
        "tasks": ["T004", "T005"],
        "status": "pending",
        "completed_tasks": [],
        "started_at": null,
        "completed_at": null
      }
    ],
    "dag": {
      "T001": {"depends": []},
      "T002": {"depends": ["T001"]},
      "T003": {"depends": ["T001"]}
    },
    "tasks": {
      "T001": {
        "id": "T001",
        "name": "实现 NotificationGroup 类",
        "wave_id": "wave-1",
        "type": "core_implementation",
        "status": "done",
        "retry_count": 0,
        "last_error": null,
        "verified": true,
        "started_at": "2026-05-06T10:38:00Z",
        "completed_at": "2026-05-06T10:45:00Z",
        "files_locked": [],
        "depends": [],
        "files_write": ["frameworks/ans/core/notification_group.h", "frameworks/ans/core/notification_group.cpp"],
        "files_read": ["frameworks/ans/core/notification_manager.h"],
        "acceptance_criteria": ["类定义完整", "基本方法实现", "编译通过"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service"],
        "evidence_required": ["源代码文件", "编译日志"],
        "risk_level": "low",
        "description": "实现 NotificationGroup 类"
      },
      "T002": {
        "id": "T002",
        "name": "实现分组创建接口",
        "wave_id": "wave-1",
        "type": "core_implementation",
        "status": "running",
        "retry_count": 1,
        "last_error": "COMPILE_ERROR: syntax error at line 42",
        "verified": false,
        "started_at": "2026-05-06T10:45:00Z",
        "completed_at": null,
        "files_locked": ["frameworks/ans/core/notification_manager.cpp"],
        "depends": ["T001"],
        "files_write": ["frameworks/ans/core/notification_manager.cpp", "interfaces/inner_api/notification_manager_interface.h"],
        "files_read": ["frameworks/ans/core/notification_group.h"],
        "acceptance_criteria": ["接口定义完整", "实现逻辑正确", "单元测试覆盖"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service_test"],
        "evidence_required": ["接口定义文档", "实现代码", "单元测试代码"],
        "risk_level": "medium",
        "description": "在 NotificationManager 中实现分组创建接口"
      },
      "T003": {
        "id": "T003",
        "name": "实现分组查询接口",
        "wave_id": "wave-1",
        "type": "core_implementation",
        "status": "pending",
        "retry_count": 0,
        "last_error": null,
        "verified": false,
        "started_at": null,
        "completed_at": null,
        "files_locked": [],
        "depends": ["T001"],
        "files_write": ["frameworks/ans/core/notification_manager.cpp"],
        "files_read": ["frameworks/ans/core/notification_group.h"],
        "acceptance_criteria": ["接口定义完整", "实现逻辑正确"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service_test"],
        "evidence_required": ["接口定义文档", "实现代码"],
        "risk_level": "medium",
        "description": "在 NotificationManager 中实现分组查询接口"
      }
    },
    "file_locks": [
      {
        "file": "frameworks/ans/core/notification_manager.cpp",
        "locked_by": "T002",
        "locked_at": "2026-05-06T10:45:00Z"
      }
    ],
    "updated_at": "2026-05-06T10:46:00Z"
  }
}
```