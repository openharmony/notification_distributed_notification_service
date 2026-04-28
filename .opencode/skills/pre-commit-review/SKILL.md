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

Before marking code as approved, verify ALL of the following:

1. **Null Pointer Safety**
   - All pointer parameters checked for nullptr before use
   - All pointer return values checked before dereference
   - Use nullptr instead of NULL or 0

2. **Buffer Safety**
   - Buffer length checked before read/write operations
   - Array index bounds checked
   - Use memcpy_s instead of memcpy
   - No reliance on null terminator for buffer boundaries

3. **Memory Safety**
   - new[] paired with delete[] (not delete)
   - No memory leaks (every allocation has corresponding free)
   - No use after free
   - Allocation size validated before malloc/new

4. **Integer Safety**
   - Division/modulo operations check divisor != 0
   - Arithmetic operations checked for overflow
   - Use fixed-width types (int32_t, uint32_t, etc.)

5. **External Data Validation**
   - All network/file/user input validated
   - Length, range, format checked
   - Use whitelist for acceptable values

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