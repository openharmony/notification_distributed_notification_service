---
name: verify-test
description: "当需要验证某个单元测试，或验证某个部件的所有单元测试时触发。通过 hdc 在 ARM 设备上运行 OpenHarmony 模块单元测试：处理无法在本地执行的 ARM32 二进制文件，完成编译、部署、运行、收集结果全流程。支持 unittest/moduletest/fuzztest/benchmark 分类、gtest_filter 精确过滤、超时控制、增量推送和崩溃诊断。 Trigger keywords: 验证单元测试, 运行单元测试, 跑单元测试, 单元测试, 部件测试, 验证测试, 跑测试, 测试二进制, 推送测试, gtest, gtest_filter, unittest, moduletest, fuzztest, benchmark, 单测, 跑一下测试, 验证某个测试, push_module_tests, run_module_tests"
---

# OpenHarmony 单元测试

通过 hdc 在 ARM 设备上运行任意 OpenHarmony 模块的测试。

## 架构

本地主机（x86_64）交叉编译为 ARM32（rk3568）。测试二进制无法在本地执行——必须推送到已连接设备并通过 `hdc shell` 运行。

```
[编译] → [推送库和测试] → [通过 hdc shell 执行] → [解析通过/失败]
```

## 测试类型

OpenHarmony 测试按类型分类，目录布局和运行方式不同：

| 类型 | 目录 | 说明 | 输出格式 |
|---|---|---|---|
| **unittest** | `tests/unittest/` | 单元测试，验证单个类/函数 | GTest: `[  PASSED  ]` / `[  FAILED  ]` |
| **moduletest** | `tests/moduletest/` | 模块测试，验证模块间交互 | GTest: `[  PASSED  ]` / `[  FAILED  ]` |
| **fuzztest** | `tests/fuzztest/` | 模糊测试，验证边界输入鲁棒性 | 无标准输出，只判断是否崩溃 |
| **benchmark** | `tests/benchmark/` | 性能基准测试 | 无标准输出，只判断是否崩溃 |

**默认只运行 unittest**。如需运行其他类型，使用 `--type` 参数指定。

## 环境配置

所有路径自动检测，需要时可通过环境变量覆盖：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OH_ROOT` | 从当前目录向上查找 `.gn` | OpenHarmony 编译根目录 |
| `HDC_PATH` | `which hdc` 或工具链路径 | hdc 二进制路径 |
| `OH_PRODUCT` | `rk3568` | 目标产品名 |
| `OH_DEVICE_LIB_DIR` | `/system/lib/platformsdk/` | 设备共享库目录 |

关键目录布局：
- **编译输出**: `out/<product>/`
- **unittest**: `out/<product>/tests/unittest/<module>/.../unittest/<test_name>`
- **moduletest**: `out/<product>/tests/moduletest/<module>/.../moduletest/<test_name>`
- **fuzztest**: `out/<product>/tests/fuzztest/<module>/.../<fuzz_test_name>`
- **benchmark**: `out/<product>/tests/benchmark/<module>/.../benchmarktest/<test_name>`
- **模块库**: `out/<product>/<subsystem>/<module>/*.so`

**设备端目录**:
- 库: `/system/lib/platformsdk/`（所有类型共用）
- unittest: `/data/local/tmp/<module>_unittest/`
- moduletest: `/data/local/tmp/<module>_moduletest/`
- fuzztest: `/data/local/tmp/<module>_fuzztest/`
- benchmark: `/data/local/tmp/<module>_benchmark/`

## 快速开始

> **路径说明**: 下文中的 `<path-to-skill>` 指 skill 的安装目录。本 skill 位于项目内 `<repo>/.opencode/skills/verify-test/`（即 `distributed_notification_service/.opencode/skills/verify-test/`）。也可在调用前导出环境变量：`SKILL_DIR=$(dirname "$(readlink -f "$0")")` 自动定位。所有脚本支持 `--help` 查看完整用法。

### 全流程（编译 → 推送 → 运行 unittest）

```bash
# 1. 编译
./build.sh --product-name rk3568 \
  --build-target distributed_notification_service \
  --build-target distributed_notification_service_unit_test \
  --ccache --no-prebuilt-push

# 2. 推送（默认只推送 unittest）
<path-to-skill>/scripts/push_module_tests.sh distributed_notification_service

# 3. 运行（默认只运行 unittest）
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service
```

### 运行 moduletest

```bash
# 编译 moduletest（需要额外编译目标）
./build.sh --product-name rk3568 \
  --build-target distributed_notification_service \
  --ccache --no-prebuilt-push

# 推送
<path-to-skill>/scripts/push_module_tests.sh distributed_notification_service --type=moduletest

# 运行
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service --type=moduletest
```

### 运行 fuzztest

```bash
<path-to-skill>/scripts/push_module_tests.sh distributed_notification_service --type=fuzztest
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service --type=fuzztest
```

### 推送所有类型并运行

```bash
<path-to-skill>/scripts/push_module_tests.sh distributed_notification_service --type=all
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service --type=all
```

### 增量重测（修复代码后）

```bash
# 重新编译
./build.sh --product-name rk3568 \
  --build-target distributed_notification_service \
  --build-target distributed_notification_service_unit_test \
  --ccache --no-prebuilt-push

# 增量推送
<path-to-skill>/scripts/push_module_tests.sh distributed_notification_service --incremental

# 带过滤运行
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service \
  --gtest_filter='NotificationSlotTest.*'
```

### 运行单个测试二进制

当只需要运行一个特定的测试二进制（而非全部测试）时：

```bash
# 只运行 notification_service_test，带 gtest_filter
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service \
  --binary=notification_service_test \
  --gtest_filter='AnsSlotServiceTest.GetEnabledForBundleSlots*'
```

### 列出测试用例名称

`--gtest_filter` 需要完整的 `TestSuiteName.TestCaseName` 格式。用 `--list-tests` 查看可用用例：

```bash
# 列出指定二进制内的所有测试用例（含 TestSuite 名称）
<path-to-skill>/scripts/run_module_tests.sh distributed_notification_service \
  --binary=notification_service_test \
  --list-tests
```

输出示例：
```
=== notification_service_test ===
AnsSlotServiceTest.
  GetEnabledForBundleSlots_00001
  GetEnabledForBundleSlots_00002
  ...
```

然后可以用 `--gtest_filter='AnsSlotServiceTest.GetEnabledForBundleSlots*'` 精确过滤。

## 脚本参考

### `push_module_tests.sh` — 推送库和测试到设备

```bash
push_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--incremental] [--libs-only] [--tests-only] [--remount] [--help]
```

选项：
- `--type=<type>`: 测试类型过滤（默认 `unittest`）。`all` 推送所有类型
- `--incremental`: 只推送本地时间戳 > 设备时间戳的文件
- `--libs-only`: 只推送共享库（所有类型共用）
- `--tests-only`: 只推送测试二进制
- `--remount`: 强制重新挂载系统分区为可写
- `--help`: 打印用法

未知 `--xxx` 参数将报错退出（避免静默吞掉拼错的选项）。脚本启动时执行设备探活（`hdc shell echo ok`），区分"无设备"与"设备 offline/unauthorized"。

推送前自动检测系统分区是否可写，只读时自动执行 `hdc target mount`。删除设备测试目录前对路径做正则断言（`^/data/local/tmp/<module>_<type>$`），MODULE 为空时拒绝执行。

### `find_module_libs.sh` — 列举模块库及其依赖

```bash
find_module_libs.sh <module_name> [product] [--symbol <name>] [--help]
```

输出：
- 模块产生的所有 `.so` 文件（按文件名去重）
- 所有库的 NEEDED 共享库依赖
- 符号可用性检查（**仅当显式传入 `--symbol <name>` 时执行**；不传则跳过该段，避免对非通知模块输出无意义的默认符号查询）

### `run_module_tests.sh` — 运行测试并收集结果

```bash
run_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--gtest-filter=<pattern>] [--timeout=<seconds>] [--verbose] [--list] [--list-tests] [--binary=<name>] [--help] [log_file]
```

选项：
- `--type=<type>`: 测试类型（默认 `unittest`）
- `--gtest-filter=<pattern>`: GTest 过滤（仅对 unittest/moduletest 有效）
- `--timeout=<seconds>`: 单个测试超时（默认: unittest/moduletest=120s, fuzztest/benchmark=60s）。**设备无 `timeout` 命令时，自动回退到主机侧 `timeout` 兜底**（额外加 15s 通信缓冲），避免测试 hang 时 skill 永久挂起
- `--verbose`: 打印完整测试输出
- `--list`: 列出设备上的测试二进制但不运行
- `--list-tests`: 列出二进制内的测试用例（使用 `--gtest_list_tests`，需配合 `--binary`）
- `--binary=<name>`: 只运行指定的测试二进制（如 `--binary=notification_service_test`）
- `--help`: 打印用法

未知 `--xxx` 参数将报错退出（避免静默吞掉拼错的选项，被误当作 `log_file`）。启动时执行设备探活，区分"无设备"与"设备 offline/unauthorized"。

结果解析逻辑：
- **unittest/moduletest**: 解析 `[  PASSED  ]` / `[  FAILED  ]` 计数
- **fuzztest/benchmark**: 只判断是否崩溃，正常退出视为通过
- **通过率**: 分母纳入崩溃和超时（崩溃二进制的用例计数未知，按 1 个失败当量计入），避免"5 个二进制 2 通过 3 崩溃 → 通过率 100%"的误导。展示格式 `通过率: X% (通过/总数=P/T)`

## 手动流程（脚本不可用时）

### 1. 编译

```bash
./build.sh --product-name rk3568 \
  --build-target <module_name> \
  --build-target <module_name>_unit_test \
  --ccache --no-prebuilt-push
```

### 2. 推送库

```bash
hdc shell "mount -o remount,rw /"

for lib in $(find out/rk3568 -maxdepth 4 -name "*.so" -path "*<module>*"); do
  name=$(basename "$lib")
  hdc file send "$lib" /data/local/tmp/"$name"
  hdc shell "cp /data/local/tmp/$name /system/lib/platformsdk/$name && chmod 644 /system/lib/platformsdk/$name"
done
```

### 3. 推送 unittest 测试

```bash
hdc shell "rm -rf /data/local/tmp/<module>_unittest && mkdir -p /data/local/tmp/<module>_unittest"

for t in $(find out/rk3568/tests/unittest -maxdepth 5 -type f -executable -path "*<module>*" ! -name "*.so" ! -name "*.abc"); do
  hdc file send "$t" /data/local/tmp/<module>_unittest/$(basename "$t")
done
hdc shell "chmod +x /data/local/tmp/<module>_unittest/*"
```

### 4. 运行测试

```bash
hdc shell "cd /data/local/tmp/<module>_unittest && \
  LD_LIBRARY_PATH=/system/lib/platformsdk:/data/local/tmp/<module>_unittest \
  ./<test_name> --gtest_filter='<pattern>' 2>&1"
```

**关键**: 必须设置 `LD_LIBRARY_PATH=/system/lib/platformsdk:/data/local/tmp/<module>_unittest`。

## 常见陷阱

- **"Read-only file system"**: 系统分区只读。推送脚本会自动执行 `hdc target mount`，如仍失败请手动执行 `hdc target mount` 后重试。
- **"symbol not found"**: 缺少依赖 `.so`。用 `find_module_libs.sh` 定位符号，然后推送对应库。
- **"cannot execute binary file"**: 在 x86 主机运行 ARM 二进制。必须在设备上运行。
- **设备上库过期**: 重新推送时间戳变更的 `.so`，或使用 `--incremental`。
- **Permission denied**: 确保 `.so` 文件 `chmod 644`，测试二进制 `chmod +x`。
- **测试崩溃 (SIGSEGV/SIGABRT)**: 检查 `SetUp()` — 可能是空指针解引用或 mock 未初始化。
- **fuzztest 正常退出但无 GTest 输出**: 正常现象，fuzztest 只判断是否崩溃。
- **推错目录**: 确保 `--type` 与推送类型一致，设备目录为 `/<module>_<type>/`。
- **gtest_filter 不匹配**: `--gtest_filter` 需要完整的 `TestSuiteName.TestCaseName` 格式。先用 `--list-tests --binary=<name>` 查看可用用例名。
- **"设备已连接但不可用"**: `hdc list targets` 显示设备但探活失败（`hdc shell echo ok` 无响应）。常见于设备 [Offline] 或 [unauthorized]。重新插拔 USB 或在设备上授权调试。
- **"主机侧兜底超时"提示**: 设备无 `timeout` 命令时，由主机 `timeout` 强制结束 `hdc shell`。设备上的测试进程可能残留，下次推送时建议 `--remount` 后清理 `/data/local/tmp/<module>_<type>/`。

## 参考文件

- `references/common-failures.md` — 详细故障分类与诊断
- `scripts/push_module_tests.sh` — 自动推送（库 + 测试，按类型分目录）
- `scripts/find_module_libs.sh` — 列举模块库及依赖
- `scripts/run_module_tests.sh` — 运行测试、收集摘要、按类型解析结果

## feature-agent 集成

本 skill 可被 **Feature-Agent 工作流** 的 **Phase 5.5: VERIFY** 阶段通过 `Feature-Verify-SubAgent` 调用。以下是集成契约。

### 调用方

`Feature-Verify-SubAgent`（`.opencode/agents/Feature/Feature-Verify-SubAgent.md`），在 Build 阶段编译通过后执行。

### 前置条件

- Build 阶段已完成，编译产物存在于 `out/<product>/`（`phases.build.status == "done"`）
- `plan.md` 中各任务的 `test_commands` 字段包含测试二进制和模块名信息

### 默认测试类型范围

| 类型 | 默认是否运行 | 说明 |
|---|---|---|
| unittest | ✅ 是 | 单元测试，GTest 格式 |
| moduletest | ✅ 是 | 模块测试，GTest 格式 |
| fuzztest | ❌ 否 | 仅当 plan.md 的 test_commands 显式包含时 |
| benchmark | ❌ 否 | 仅当 plan.md 的 test_commands 显式包含时 |

### 调用流程

```bash
# 1. 推送 unittest
<path-to-skill>/scripts/push_module_tests.sh <module_name> --type=unittest
<path-to-skill>/scripts/run_module_tests.sh <module_name> --type=unittest

# 2. 推送 moduletest
<path-to-skill>/scripts/push_module_tests.sh <module_name> --type=moduletest
<path-to-skill>/scripts/run_module_tests.sh <module_name> --type=moduletest
```

### 无设备时的行为

设备探活失败（`hdc shell echo ok` 无响应）时，**不报错退出**，而是返回 `VERIFY_SKIPPED`：

```json
{
  "verify_status": "skipped",
  "skip_reason": "no_device",
  "detail": "hdc list targets 无设备 或 设备 offline/unauthorized"
}
```

调用方将 `phases.verify.status` 标记为 `skipped`，流程继续进入 Doc 阶段（不阻塞）。

### 退出码语义（调用方解读）

| 脚本 | 退出码 0 | 退出码 1 | 退出码 2 |
|---|---|---|---|
| `push_module_tests.sh` | 推送完成 | 推送流程出错（环境问题） | 未知选项 |
| `run_module_tests.sh` | 全部通过（无失败/崩溃/超时） | 有失败/崩溃/超时；**或**前置错误（无 hdc/设备不可用） | 未知选项 |

**注意**：`run_module_tests.sh` 的退出码 1 同时承载"测试失败"和"前置错误"两种语义。调用方应先确保 push 成功（排除环境问题），再解读 run 的退出码 1 为"测试有失败"。

### 输出产物

调用方需写入 `{kb_dir}/verify-log.md`，内容模板见 `Feature-Verify-SubAgent.md` 的"文件输出"段。

### 失败任务定位

测试失败时，调用方需将失败的测试二进制映射回 plan.md 中的任务：

| 映射策略 | 方法 |
|---|---|
| 直接匹配 | 失败二进制名 → plan.md 中 task 的 `test_commands` 字段包含该二进制名 |
| 模糊匹配 | 失败的 TestSuite 名 → task 的 `files_write` 中的测试文件路径 |
| 无法匹配 | 标记为 `unmapped`，建议 `human_review` |