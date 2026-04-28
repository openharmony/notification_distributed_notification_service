---
name: pre-commit-review
description: "Pre-commit code review for OpenHarmony projects based on C++ coding standards. Use when reviewing code before commit, checking local changes, or verifying OpenHarmony style compliance. Triggers on pre-commit review requests, git diff/staged changes inspection, and code quality checks."
---

# Pre-Commit Code Review

## Overview

Perform comprehensive code review on local git changes before commit, ensuring compliance with OpenHarmony C++ coding standards. Output an interactive HTML report with fix suggestions, priority filtering, and **checked file scope**.

## Workflow

### Step 1: Collect File Scope

**CRITICAL**: Record all files checked during review.

#### For Git Changes Review

```bash
# Get staged changes
git diff --cached --name-only

# Get unstaged changes  
git diff --name-only

# Get both staged and unstaged
git diff HEAD --name-only
```

#### For Full Project Review

Scan project directories to collect all source files:

```bash
# Collect .cpp files
find services/ -name "*.cpp" -type f

# Collect .h files  
find services/ -name "*.h" -type f
```

#### Build File Scope Data Structure

Create a data structure tracking:

```
FileScope = {
    directories: [
        {
            path: "services/ans/src/",
            files: [
                { name: "advanced_notification_service.cpp", issues: [P0:2, P1:1] },
                { name: "notification_slot_filter.cpp", issues: [] },
                ...
            ],
            totalFiles: 96,
            filesWithIssues: 5,
            filesPassed: 91
        },
        ...
    ],
    totalFiles: 170,
    totalFilesWithIssues: 7,
    totalFilesPassed: 163
}
```

### Step 2: Review Each File

Check against all categories defined in [references/openharmony-cpp-full-standards.md](references/openharmony-cpp-full-standards.md).

Use grep/regex patterns for quick scanning:

| Priority | Category | Search Pattern | Description |
|----------|----------|----------------|-------------|
| **P0** | **NULL usage** | `\bNULL\b` | 使用NULL而非nullptr，类型不安全 |
| **P0** | **C-style cast** | `\(\w+\*\)` | C风格强制转换，缺乏类型安全检查 |
| **P0** | **Raw new[] without delete[]** | `new\s+\w+\[` | 内存泄漏风险 |
| **P0** | **Division without check** | `/\s*\w+\s*[;)]` | 除零错误风险 |
| **P0** | **Buffer access without bounds** | `\[\s*\w+\s*\]` | 数组越界风险 |
| **P0** | **Missing nullptr check** | Manual review | 函数参数/返回值未校验nullptr |
| **P0** | **Missing length check** | Manual review | 缓冲区操作未校验长度 |
| **P0** | **Unvalidated external data** | Manual review | 外部数据未进行合法性校验 |
| **P0** | **Integer overflow risk** | Manual review | 整数运算可能导致溢出 |
| **P0** | **Use after free** | Manual review | 内存释放后继续使用 |
| **P0** | **Dangling pointer** | Manual review | 返回局部变量指针 |
| **P0** | **Missing size check before alloc** | Manual review | 内存申请前未校验大小 |
| **P0** | **strncpy/strcpy unsafe usage** | `strncpy|strcpy|sprintf` | 不安全的字符串操作 |
| **P1** | Duplicate include | Check same header twice | 重复包含头文件 |
| **P1** | Missing header guard | No `#ifndef` in .h | 缺少头文件保护 |
| **P1** | Uninitialized member | Class members without `{}` | 成员变量未初始化 |
| **P1** | Missing explicit | Single-param constructor | 单参数构造函数未声明explicit |
| **P1** | Missing override | Virtual function without override | 虚函数重写未声明override |
| **P1** | Macro constant | `#define\s+[A-Z_]+\s+[0-9]` | 使用宏定义常量 |
| **P1** | long type | `\blong\b` | 使用long类型（32/64位不兼容） |
| **P2** | const static order | `const\s+static` | const static顺序错误 |
| **P2** | Magic number | Unnamed numeric literals | 魔鬼数字 |
| **P2** | Missing comment | Public function without doc | 公有函数缺少注释 |

**IMPORTANT**: All security-related issues (memory safety, null pointer, buffer overflow, integer overflow, use-after-free) MUST be classified as **P0** and block submission.

### Security Coding Checklist (P0 - Block Submission)

**来源：华为C/C++安全编码规范 + OpenHarmony安全编程指南**

详细检视清单请参考：[references/security-coding-checklist.md](references/security-coding-checklist.md)

#### 必须检查的P0安全编码问题（33项）

| 类别 | 检视点数量 | 关键检查项 |
|------|-----------|-----------|
| **内存安全** | 9项 | 分配大小校验、new[]配delete[]、memcpy_s/strcpy_s |
| **指针安全** | 6项 | nullptr校验、禁止NULL、禁止悬空指针、禁止C风格转换 |
| **缓冲区安全** | 7项 | 边界校验、指定长度、不依赖'\0'终止符 |
| **整数安全** | 6项 | 溢出检查、除零检查、位运算类型 |
| **外部数据** | 4项 | 网络/文件/IPC/用户输入校验 |
| **并发安全** | 1项 | 共享数据加锁 |
| **密码安全** | 2项 | 禁止硬编码密钥、禁止打印敏感信息 |

#### 详细检视清单

1. **内存安全 (P0-01 ~ P0-09)**
   - [ ] P0-01: 分配前是否校验大小 (size != 0 && size <= MAX)
   - [ ] P0-02: 分配失败是否检查返回值 (ptr != nullptr)
   - [ ] P0-03: 是否禁止new[0] (length == 0校验)
   - [ ] P0-04: new[]是否配delete[]而非delete
   - [ ] P0-05: 释放后是否置nullptr
   - [ ] P0-06: 是否禁止释放后继续使用 (UAF)
   - [ ] P0-07: 是否使用memcpy_s而非memcpy
   - [ ] P0-08: 是否使用strcpy_s而非strcpy
   - [ ] P0-09: 是否使用snprintf而非sprintf

2. **指针安全 (P0-10 ~ P0-15)**
   - [ ] P0-10: 是否使用nullptr而非NULL
   - [ ] P0-11: 参数指针是否校验nullptr
   - [ ] P0-12: 返回值指针是否校验
   - [ ] P0-13: 成员指针是否校验
   - [ ] P0-14: 是否禁止返回局部变量指针
   - [ ] P0-15: 是否使用C++类型转换而非C风格

3. **缓冲区安全 (P0-16 ~ P0-21)**
   - [ ] P0-16: 数组索引是否校验边界
   - [ ] P0-17: 缓冲区写入是否校验剩余空间
   - [ ] P0-18: 缓冲区读取是否校验数据长度
   - [ ] P0-19: 是否禁止依赖'\0'终止符确定边界
   - [ ] P0-20: 创建string前是否校验指针非空
   - [ ] P0-21: 构造string是否指定长度

4. **整数安全 (P0-22 ~ P0-26)**
   - [ ] P0-22: 加法运算是否检查溢出
   - [ ] P0-23: 乘法运算是否检查溢出
   - [ ] P0-24: 除法前是否检查除数不为0
   - [ ] P0-25: 取模前是否检查模数不为0
   - [ ] P0-26: 是否禁止有符号数位运算

5. **外部数据校验 (P0-27 ~ P0-30)**
   - [ ] P0-27: 网络数据是否校验
   - [ ] P0-28: 文件数据是否校验
   - [ ] P0-29: IPC数据是否校验
   - [ ] P0-30: 用户输入是否校验

6. **并发安全 (P0-31)**
   - [ ] P0-31: 共享数据是否加锁

7. **密码安全 (P0-32 ~ P0-33)**
   - [ ] P0-32: 是否禁止硬编码密钥/密码
   - [ ] P0-33: 是否禁止日志打印敏感信息

#### 检视时必须使用以下方式

```bash
# 自动检测命令
grep -n "\bNULL\b" *.cpp *.h              # P0-10: NULL使用
grep -n "\(\w+\*\)" *.cpp *.h             # P0-15: C风格转换
grep -n "memcpy\b" *.cpp *.h              # P0-07: memcpy使用
grep -n "strcpy\b" *.cpp *.h              # P0-08: strcpy使用
grep -n "sprintf\b" *.cpp *.h             # P0-09: sprintf使用
grep -n "password\|secret\|key" *.cpp *.h # P0-32: 硬编码敏感信息

# 人工审查项（无法自动检测）
# P0-01~06, P0-11~21, P0-22~31, P0-33: 需要人工逐行审查代码逻辑
```

### Step 3: Generate HTML Report

Use the template in [assets/report_template.html](assets/report_template.html) and fill in these variables:

#### Required Variables

| Variable | Description |
|----------|-------------|
| `${FILE_SCOPE_SECTION}` | HTML for checked file scope (directory cards) |
| `${TOTAL_FILES}` | Total number of files checked |
| `${FILES_WITH_ISSUES}` | Number of files with issues |
| `${FILES_PASSED}` | Number of files passed |
| `${P0_COUNT}` | Number of P0 issues |
| `${P1_COUNT}` | Number of P1 issues |
| `${P2_COUNT}` | Number of P2 issues |
| `${PASS_COUNT}` | Number of compliance items |
| `${P0_ISSUES_SECTION}` | HTML for P0 issues |
| `${P1_ISSUES_SECTION}` | HTML for P1 issues |
| `${P2_ISSUES_SECTION}` | HTML for P2 issues |
| `${RECOMMENDATION_CLASS}` | block/warn/info |
| `${RECOMMENDATION_TITLE}` | Recommendation header |
| `${RECOMMENDATION_TEXT}` | Recommendation details |
| `${COMPLIANCE_ITEMS}` | HTML for passed checks |

#### File Scope Section HTML Template

Generate for each directory:

```html
<div class="scope-section">
    <h2>📁 检查文件范围</h2>
    <div class="scope-summary">
        <span class="stat"><strong>总文件数:</strong> ${TOTAL_FILES} 个</span>
        <span class="stat"><strong>发现问题文件:</strong> ${FILES_WITH_ISSUES} 个</span>
        <span class="stat"><strong>无问题文件:</strong> ${FILES_PASSED} 个</span>
    </div>
    <div class="scope-grid">
        <!-- Directory card for each directory -->
        <div class="scope-card ${CARD_CLASS}">
            <div class="dir-name">
                <span>📂 ${DIRECTORY_PATH}</span>
                <span>
                    ${ISSUE_BADGES}
                    <span class="file-count">${FILE_COUNT} 文件</span>
                </span>
            </div>
            <ul class="file-list">
                <li class="${FILE_CLASS}">${FILE_STATUS} ${FILE_NAME} ${ISSUE_COUNT}</li>
                <!-- More files... -->
            </ul>
        </div>
    </div>
</div>
```

#### Directory Card Class Logic

| Condition | Class | Border Color |
|-----------|-------|--------------|
| Has P0 issues | `has-issue` | Red (P0) |
| Has P1/P2 issues | `has-p1` | Orange (P1) |
| No issues | `no-issue` | Green (pass) |

#### File List Item Class Logic

| Condition | Class | Status Icon |
|-----------|-------|-------------|
| Has P0 issues | `file-with-issue` | 🔴 |
| Has P1/P2 issues | `file-with-p1` | ⚠️ |
| No issues | `file-pass` | ✓ |

#### Issue Card HTML Template

For each issue, generate:

```html
<div class="issue-card p0">
    <div class="issue-header">
        <div class="file-info">
            <span class="path">services/distributed/src/tlv_box.cpp</span>
            <span class="line">Line: 111</span>
        </div>
        <span class="category">内存安全</span>
    </div>
    <div class="issue-body">
        <div class="description">
            <p><strong>问题:</strong> 使用NULL而非nullptr</p>
            <p><strong>原因:</strong> NULL在C++中是整数常量，无法区分指针和整数类型，不安全</p>
            <p><strong>规范:</strong> 规则10.1.3 使用nullptr</p>
        </div>
        <div class="code-block">
            <span class="line-number">111:</span> <span class="highlight">if (byteBuffer_ != NULL)</span>
        </div>
        <div class="fix-section">
            <h4>💡 修复建议</h4>
            <div class="fix-code">if (byteBuffer_ != nullptr)</div>
        </div>
    </div>
</div>
```

#### Recommendation Logic

| Condition | Class | Title | Text |
|-----------|-------|-------|------|
| P0 > 0 | `block` | 🚫 阻止提交 | 存在严重问题，必须修复后才能提交 |
| P0 == 0 && P1 > 0 | `warn` | ⚠️ 廖议修复 | 存在重要问题，建议修复后再合并 |
| P0 == 0 && P1 == 0 && P2 > 0 | `info` | 💡 可选优化 | 仅存在风格问题，可根据时间选择修复 |
| All == 0 | `info` | ✅ 可以提交 | 代码符合OpenHarmony编码规范 |

### Step 4: Write Report

Save HTML report to project directory:

```
CODE_REVIEW_REPORT.html
```

## Coding Standards Reference

See [references/openharmony-cpp-full-standards.md](references/openharmony-cpp-full-standards.md) for complete OpenHarmony C++ coding standards, including:

- **C++ Style Guide**: Naming, formatting, comments, classes, modern C++
- **Secure Coding Guide**: Memory safety, integer overflow, buffer safety
- **32/64-bit Portability**: Data types, pointer handling, structure alignment

## HTML Report Features

The generated HTML report includes:

1. **File Scope Section** - Shows all checked files organized by directory:
   - Total files count summary
   - Directory cards with file lists
   - Expand/collapse for each directory
   - Color-coded status indicators (🔴 P0 / ⚠️ P1 / ✓ passed)

2. **Summary Cards** - Visual counts of each priority level

3. **Priority Filter** - Click buttons to show/hide issues by priority

4. **Issue Cards** - Each issue shows:
   - File path and line number
   - Category tag
   - Problem description and impact
   - Original code with highlight
   - Fix suggestion with corrected code

5. **Recommendation Section** - Action guidance based on findings

6. **Compliance Section** - List of passed checks

## Usage Examples

**Example 1: Review staged changes with file scope**
```
User: Review my staged changes before commit

Process:
1. Run `git diff --cached --name-only` → collect file list
2. Record all checked files in FileScope structure
3. Read each modified file
4. Apply checklist, track which files have issues
5. Generate HTML report with FILE_SCOPE_SECTION
6. Save to CODE_REVIEW_REPORT.html
```

**Example 2: Full project review**
```
User: Review the entire services/ directory

Process:
1. Run `find services/ -name "*.cpp"` → collect 170 files
2. Build FileScope with all directories and files
3. Scan each file for P0/P1/P2 patterns
4. Mark files with issues in FileScope
5. Generate complete HTML report showing all checked files
6. Save to CODE_REVIEW_REPORT.html
```

**Example 3: Quick P0 check**
```
User: Are there any critical issues?

Process:
1. Get modified files, record in FileScope
2. Only scan P0 patterns (NULL, C-cast, memory)
3. Mark files with P0 issues
4. Generate summary report with file scope
```

## File Scope Data Collection Example

When reviewing, build this structure:

```json
{
  "totalFiles": 170,
  "filesWithIssues": 7,
  "filesPassed": 163,
  "directories": [
    {
      "path": "services/ans/src/",
      "totalFiles": 96,
      "filesWithIssues": 5,
      "issues": { "P0": 2, "P1": 55 },
      "files": [
        { "name": "aes_gcm_helper.cpp", "issues": ["P0:1"] },
        { "name": "notification_subscriber_manager.cpp", "issues": ["P1:6"] },
        { "name": "notification_preferences_database.cpp", "issues": ["P1:47"] },
        { "name": "notification_slot_filter.cpp", "issues": [] },
        ...
      ]
    },
    {
      "path": "services/distributed/src/",
      "totalFiles": 52,
      "filesWithIssues": 1,
      "issues": { "P0": 12, "P2": 1 },
      "files": [
        { "name": "tlv_box/tlv_box.cpp", "issues": ["P0:8", "P2:1"] },
        { "name": "distributed_preferences.cpp", "issues": [] },
        ...
      ]
    },
    {
      "path": "services/reminder/src/",
      "totalFiles": 14,
      "filesWithIssues": 0,
      "issues": {},
      "files": [
        { "name": "reminder_data_manager.cpp", "issues": [] },
        ...
      ]
    }
  ]
}
```