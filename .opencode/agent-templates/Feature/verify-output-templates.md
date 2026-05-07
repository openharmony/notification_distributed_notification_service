# 验证输出模板

本文件包含 Feature-Verify-SubAgent 使用的验证输出模板。

**重要约定**：所有过程文档存放在 `.opencode/kb/features/${feature-name}/` 目录下，其中 `${feature-name}` 为需求名称。

## 1. 变更范围审计失败模板

```text
VERIFY_FAIL
reason: OUT_OF_SCOPE
detail: 发现越界修改
severity: high
escalate: true

越界文件:
- <file>: <原因说明>

建议: 回滚越界修改,保持在批准的文件范围内
```

---

## 2. 编译验证失败模板

```text
VERIFY_FAIL
reason: COMPILE_ERROR
detail: 编译失败
severity: high
escalate: false

编译错误:
- <错误信息>

建议: 修复编译错误,不改变实现逻辑
```

---

## 3. 测试验证失败模板

```text
VERIFY_FAIL
reason: TEST_FAILURE
detail: 测试失败
severity: high
escalate: false

失败测试:
- <测试用例>: <失败原因>

建议: 修复功能问题,保证测试通过
```

---

## 4. 验收标准不满足失败模板

```text
VERIFY_FAIL
reason: ACCEPTANCE_NOT_MET
detail: 验收标准未满足
severity: high
escalate: false

未满足的验收标准:
- <验收标准>: <具体问题>

建议: 修复功能缺陷,满足验收标准
```

---

## 5. 代码质量违规失败模板

```text
VERIFY_FAIL
reason: QUALITY_VIOLATION
detail: 代码质量未达标
severity: medium
escalate: false

质量违规:
- <违规项>: <具体问题>

建议: 在任务边界内改善代码质量
```

---

## 6. 接口兼容性破坏失败模板

```text
VERIFY_FAIL
reason: INTERFACE_INCOMPATIBLE
detail: 接口兼容性被破坏
severity: high
escalate: true

兼容性问题:
- <接口>: <问题说明>

建议: 保持接口向后兼容,或上报用户决策
```

---

## 7. 测试覆盖不足失败模板

```text
VERIFY_FAIL
reason: TEST_COVERAGE_INSUFFICIENT
detail: 测试覆盖不足
severity: medium
escalate: false

覆盖不足:
- <场景>: 缺少测试

建议: 补充测试用例,覆盖所有功能点
```

---

## 8. 验证通过输出模板

```text
VERIFY_PASS
task_id: <task_id>
task_name: <task_name>
task_type: <task_type>
wave_id: <wave_id>

验证结果:
✅ 变更范围审计通过 - 所有修改都在批准范围内
✅ 编译验证通过 - 无编译错误和警告
✅ 测试验证通过 - 所有测试用例执行成功
✅ 验收标准满足 - 所有验收标准已验证
✅ 代码质量达标 - 符合代码规范和最佳实践
✅ 接口兼容性保持 - 未破坏现有接口兼容性
✅ 测试覆盖充分 - 测试覆盖所有功能点

详细验证信息:
- 修改文件数: <N>
- 执行测试数: <M>
- 通过测试数: <M>
- 验收标准数: <N>
- 满足验收标准数: <N>

验证日志已写入: .opencode/kb/features/${feature-name}/verify-log.md
```

---

## 9. 验证失败通用输出模板

```text
VERIFY_FAIL
task_id: <task_id>
task_name: <task_name>
task_type: <task_type>
wave_id: <wave_id>

失败原因: <reason>
详情: <detail>
严重程度: <severity> (high/medium/low)

影响范围:
- 受影响的文件: <列出>
- 受影响的测试: <列出>
- 受影响的验收标准: <列出>

建议: <建议>

修复建议:
1. <具体修复步骤1>
2. <具体修复步骤2>
3. <具体修复步骤3>

<失败模板的具体内容>
```

---

## 10. 验证日志记录模板

```text
## 验证记录 - <timestamp>

### 任务信息
- 任务ID: <task_id>
- 任务名称: <task_name>
- 任务类型: <task_type>
- Wave: <wave_id>

### 验证层1: 变更范围审计
- 结果: <通过/失败>
- 检查文件数: <N>
- 批准修改文件数: <M>
- 实际修改文件数: <N>
- 越界文件: <如有失败，列出>
- 详情: <如有失败，记录详情>

### 验证层2: 编译验证
- 结果: <通过/失败>
- 编译命令: <命令>
- 编译时间: <时间>
- 编译错误数: <N>
- 编译警告数: <M>
- 详情: <如有失败，记录详情>

### 验证层3: 测试验证
- 结果: <通过/失败>
- 测试命令: <命令>
- 总测试数: <N>
- 通过测试数: <M>
- 失败测试数: <K>
- 测试覆盖率: <百分比>
- 详情: <如有失败，记录详情>

### 验证层4: 验收标准验证
- 结果: <通过/失败>
- 总验收标准数: <N>
- 满足验收标准数: <M>
- 未满足验收标准: <如有失败，列出>
- 详情: <如有失败，记录详情>

### 验证层5: 代码质量验证
- 结果: <通过/失败>
- 代码规范检查: <通过/失败>
- 命名规范检查: <通过/失败>
- 日志规范检查: <通过/失败>
- 详情: <如有失败，记录详情>

### 验证层6: 接口兼容性验证
- 结果: <通过/失败>
- 公共接口检查: <通过/失败>
- 接口签名检查: <通过/失败>
- 兼容性问题: <如有失败，列出>
- 详情: <如有失败，记录详情>

### 验证层7: 测试覆盖验证
- 结果: <通过/失败>
- 正常场景测试: <有/无>
- 边界场景测试: <有/无>
- 异常场景测试: <有/无>
- 性能场景测试: <有/无>
- 缺少测试的场景: <如有失败，列出>
- 详情: <如有失败，记录详情>

### 最终结论
- 验证结果: <通过/失败>
- 失败原因: <如有失败>
- 失败类型: <如有失败>
- 修复建议: <如有失败>
```