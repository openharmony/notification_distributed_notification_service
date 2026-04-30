---
description: Auto-generate commit/issue, handle conflicts, push and create PR+Issue
---

执行完整提交工作流，commit message 和 issue title 由 AI 自动生成，包含冲突自动处理。

## 执行步骤

### 1. 分析代码变更
检查当前所有变更:
!`git status`
!`git branch --show-current`
!`git diff --stat`
!`git diff`

基于变更内容分析并生成:
- **Commit Message**: 简洁概括变更内容 (一句话，符合 OpenHarmony 规范)
- **Issue Title**: 描述相关的功能需求或问题

### 2. 询问 Co-Author
使用 question tool 询问用户:
"请输入 Co-Authored-By 的名称 (例如: Agent、Claude、Copilot 等)"

将用户回答用于 commit message 的 Co-Authored-By 行。

### 3. Git 提交
执行:
- git add 所有变更文件
- git commit --signoff -m "<生成的commit message>\n\nCo-Authored-By: <用户输入>"
- 验证提交成功 (git log -1)

### 4. Push (含冲突处理)
尝试: git push origin <当前分支>

**若 push 成功**: 继续下一步

**若 push 失败 (本地落后于远程)**:
1. 执行 git pull --rebase origin <当前分支>
2. 尝试自动解决简单冲突 (git status 查看冲突文件)
3. 若成功: git push origin <当前分支>
4. 若失败: git rebase --abort，输出提示:
   "Push 冲突无法自动解决，请手动处理后再执行 /submit"
   列出冲突文件，中止工作流

### 5. Rebase 到上游最新 (解决 PR 冲突)
确保 PR 与上游 master 无冲突:

1. 检查是否有 upstream remote:
   !`git remote -v | grep upstream || echo "no-upstream"`

2. 若无 upstream，添加:
   git remote add upstream https://gitcode.com/openharmony/notification_distributed_notification_service.git

3. Fetch upstream:
   git fetch upstream

4. Rebase:
   git rebase upstream/master

5. **若 rebase 成功**: git push --force origin <当前分支>

6. **若 rebase 失败 (冲突)**:
   - git rebase --abort
   - 输出提示: "PR 冲突无法自动解决，请手动 rebase upstream/master"
   - 列出冲突文件
   - 中止工作流

### 6. 创建/更新 PR
目标仓库: openharmony/notification_distributed_notification_service

1. 查询现有 PR 列表:
   使用 gitcode_list_pull_requests(owner=openharmony, repo=notification_distributed_notification_service)

2. 检查是否有同 head branch 的 PR:
   - head 格式: stepend98:<当前分支名>

3. **若已存在**: 更新现有 PR (gitcode_update_pull_request)
   - 更新 body 添加 issue 链接

4. **若不存在**: 创建新 PR (gitcode_create_pull_request)
   - title: 使用生成的 commit message
   - head: stepend98:<当前分支>
   - base: master
   - body: 变更说明摘要

### 7. 创建 Issue
目标仓库: openharmony/notification_distributed_notification_service

使用 gitcode_create_issue:
- owner: openharmony
- repo: notification_distributed_notification_service
- title: AI 生成的 issue title
- body: 简要描述问题/需求背景

记录返回的 issue number。

### 8. 关联 PR 和 Issue
使用 gitcode_update_pull_request 更新 PR:
- 在 body 中添加: "Related Issue: #<issue-number>"
- 或使用 "Fixes #<issue-number>" 格式

### 9. 输出结果摘要
汇总输出以下信息:
- Commit: <sha> <commit message>
- Branch: <分支名>
- PR: <PR URL>
- Issue: <Issue URL>
- 冲突处理: 若有冲突处理过程，说明处理结果

## 注意事项

- 自动冲突解决仅处理简单情况，复杂冲突需用户手动处理
- force push 仅在 rebase upstream/master 成功后执行
- 所有操作在中止时会保留 git 原始状态，用户可手动继续