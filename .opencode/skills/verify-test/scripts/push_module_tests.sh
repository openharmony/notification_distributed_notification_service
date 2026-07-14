#!/bin/bash
# push_module_tests.sh
# 推送模块共享库和测试二进制到 ARM 设备（通过 hdc）。
#
# 用法: push_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--incremental] [--libs-only] [--tests-only] [--remount]
#
# 选项:
#   --type=<type>   测试类型过滤 (默认: unittest)
#                   all: 推送所有类型; unittest/moduletest/fuzztest/benchmark: 只推送对应类型
#   --incremental   只推送本地时间戳 > 设备时间戳的文件
#   --libs-only     只推送共享库（跳过测试二进制）
#   --tests-only    只推送测试二进制（跳过共享库）
#   --remount       强制重新挂载系统分区为可写（已可写时跳过）

set -euo pipefail

MODULE=""
TEST_TYPE="unittest"
INCREMENTAL=0
LIBS_ONLY=0
TESTS_ONLY=0
FORCE_REMOUNT=0

for arg in "$@"; do
  case "$arg" in
    --type=*)       TEST_TYPE="${arg#--type=}"; ;;
    --incremental)  INCREMENTAL=1 ;;
    --libs-only)    LIBS_ONLY=1 ;;
    --tests-only)   TESTS_ONLY=1 ;;
    --remount)      FORCE_REMOUNT=1 ;;
    --help|-h)      sed -n '2,14p' "$0"; exit 0 ;;
    --*)            echo "错误: 未知选项 '$arg' (运行 --help 查看可用选项)" >&2; exit 2 ;;
    *)  if [ -z "$MODULE" ]; then MODULE="$arg"; fi ;;
  esac
done

if [ -z "$MODULE" ]; then
  echo "用法: push_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--incremental] [--libs-only] [--tests-only] [--remount]" >&2
  echo "示例: push_module_tests.sh distributed_notification_service --type=unittest" >&2
  exit 1
fi

VALID_TYPES="unittest moduletest fuzztest benchmark all"
if ! echo "$VALID_TYPES" | grep -qw "$TEST_TYPE"; then
  echo "错误: 无效测试类型 '$TEST_TYPE'。可选: unittest, moduletest, fuzztest, benchmark, all" >&2
  exit 1
fi

if [ "$LIBS_ONLY" -eq 1 ] && [ "$TESTS_ONLY" -eq 1 ]; then
  echo "错误: --libs-only 和 --tests-only 不能同时使用" >&2
  exit 1
fi

PRODUCT="${OH_PRODUCT:-rk3568}"
DEVICE_LIB_DIR="${OH_DEVICE_LIB_DIR:-/system/lib/platformsdk}"
DEVICE_TEST_BASE="/data/local/tmp"

# 定位 OpenHarmony 根目录
OH_ROOT="${OH_ROOT:-}"
if [ -z "$OH_ROOT" ]; then
  CWD="$(pwd)"
  d="$CWD"
  while [ "$d" != "/" ]; do
    if [ -f "$d/.gn" ]; then OH_ROOT="$d"; break; fi
    d="$(dirname "$d")"
  done
fi
if [ -z "$OH_ROOT" ]; then
  echo "错误: 无法定位 OpenHarmony 根目录。请设置 OH_ROOT 或在源码树内运行。" >&2
  exit 1
fi
echo "OpenHarmony 根目录: $OH_ROOT"

OUT_DIR="$OH_ROOT/out/$PRODUCT"
if [ ! -d "$OUT_DIR" ]; then
  echo "错误: $OUT_DIR 不存在。请先编译。" >&2
  exit 1
fi

# 定位 hdc
HDC="${HDC_PATH:-}"
if [ -z "$HDC" ]; then
  HDC="$(command -v hdc 2>/dev/null || true)"
fi
if [ -z "$HDC" ]; then
  for path in "$OH_ROOT"/prebuilts/hdc/*/hdc /home/*/toolchains/hdc; do
    [ -x "$path" ] && HDC="$path" && break
  done
fi
if [ -z "$HDC" ] || ! "$HDC" list targets 2>/dev/null | grep -q .; then
  echo "错误: hdc 未找到或无设备连接。请设置 HDC_PATH。" >&2
  exit 1
fi
# 设备探活: 区分"无设备"与"设备不可用 (offline/unauthorized)"
PROBE=$("$HDC" shell "echo ok" 2>/dev/null | tr -d '\r')
if [ "$PROBE" != "ok" ]; then
  echo "错误: 设备已连接但不可用 (可能 offline/unauthorized)。请检查: hdc list targets" >&2
  echo "  若显示 [unauthorized]，请在设备上授权调试；若显示 [Offline]，请重连 USB。" >&2
  exit 1
fi
echo "使用 hdc: $HDC"

# 重新挂载系统分区
check_rw() {
  "$HDC" shell "mount | grep ' / ' | grep -q 'rw,'" 2>/dev/null
}
if [ "$FORCE_REMOUNT" -eq 1 ] || ! check_rw; then
  echo "将系统分区重新挂载为可写..."
  "$HDC" target mount 2>/dev/null || true
  if ! check_rw; then
    "$HDC" shell "mount -o remount,rw /" 2>/dev/null || true
  fi
  if ! check_rw; then
    echo "错误: 系统分区仍为只读。库推送将失败。" >&2
    echo "请手动执行: $HDC target mount" >&2
    exit 1
  fi
fi

# 辅助函数: 获取设备文件时间戳
device_mtime() {
  local dev_path="$1"
  local ts
  ts=$("$HDC" shell "stat -c '%Y' '$dev_path' 2>/dev/null" | tr -d '\r' || true)
  echo "${ts:-0}"
}

push_libs() {
  echo ""
  echo "=== 推送模块库 ==="

  local -a LIBS=()
  local -a SEEN_BASENAMES=()

  for search_dir in "$OUT_DIR" "$OUT_DIR/lib.unstripped" "$OUT_DIR/innerkits/ohos-arm"; do
    if [ ! -d "$search_dir" ]; then continue; fi
    while IFS= read -r lib; do
      [ -z "$lib" ] && continue
      local bname="$(basename "$lib")"
      local seen=0
      for s in "${SEEN_BASENAMES[@]}"; do
        [ "$s" = "$bname" ] && seen=1 && break
      done
      if [ "$seen" -eq 0 ]; then
        LIBS+=("$lib")
        SEEN_BASENAMES+=("$bname")
      fi
    done < <(find "$search_dir" -maxdepth 4 -type f -name "*.so" -path "*$MODULE*" 2>/dev/null)
  done

  if [ ${#LIBS[@]} -eq 0 ]; then
    echo "  未找到模块 '$MODULE' 的 .so 文件。"
    return
  fi

  local pushed=0 skipped=0
  for lib in "${LIBS[@]}"; do
    local bname="$(basename "$lib")"
    local dev_path="$DEVICE_LIB_DIR/$bname"

    if [ "$INCREMENTAL" -eq 1 ]; then
      local dev_ts="$(device_mtime "$dev_path")"
      local local_ts="$(stat -c '%Y' "$lib" 2>/dev/null || echo 0)"
      if [ "$dev_ts" -ge "$local_ts" ] && [ "$dev_ts" -gt 0 ]; then
        echo "  [跳过] $bname (设备版本相同或更新)"
        skipped=$((skipped + 1))
        continue
      fi
    fi

    "$HDC" file send "$lib" /data/local/tmp/"$bname" 2>/dev/null
    "$HDC" shell "cp /data/local/tmp/$bname $dev_path && chmod 644 $dev_path" 2>/dev/null
    "$HDC" shell "rm /data/local/tmp/$bname" 2>/dev/null

    if "$HDC" shell "ls $dev_path" 2>/dev/null | tr -d '\r' | grep -q "$bname"; then
      echo "  [成功] $bname -> $dev_path"
      pushed=$((pushed + 1))
    else
      echo "  [失败] $bname — 推送失败！" >&2
    fi
  done
  echo "  已推送: $pushed, 已跳过: $skipped, 总计: ${#LIBS[@]}"
}

push_tests_by_type() {
  local type="$1"
  local search_base="$OUT_DIR/tests/$type"
  local device_dir="$DEVICE_TEST_BASE/${MODULE}_${type}"

  # 防御: 防止 MODULE 为空或异常导致 rm -rf 危险路径
  if ! [[ "$device_dir" =~ ^/data/local/tmp/[a-z0-9_.-]+_[a-z]+$ ]]; then
    echo "错误: 计算出的设备路径异常 '$device_dir'，拒绝执行 rm -rf" >&2
    return 1
  fi

  echo ""
  echo "=== 推送 $type 测试二进制 ==="

  "$HDC" shell "rm -rf $device_dir && mkdir -p $device_dir" 2>/dev/null

  local -a TESTS=()
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    TESTS+=("$t")
  done < <(find "$search_base" -maxdepth 6 -type f -executable -path "*$MODULE*" \
    ! -name "*.so" ! -name "*.abc" ! -name "*.py" ! -name "*.sh" ! -name "*.txt" ! -name "*.xml" 2>/dev/null || true)

  if [ ${#TESTS[@]} -eq 0 ]; then
    echo "  未找到模块 '$MODULE' 的 $type 测试二进制。"
    echo "  搜索路径: $search_base (最大深度 6, 匹配 *$MODULE*)"
    return
  fi

  local pushed=0
  for t in "${TESTS[@]}"; do
    local bname="$(basename "$t")"
    local dev_path="$device_dir/$bname"

    if [ "$INCREMENTAL" -eq 1 ]; then
      local dev_ts="$(device_mtime "$dev_path")"
      local local_ts="$(stat -c '%Y' "$t" 2>/dev/null || echo 0)"
      if [ "$dev_ts" -ge "$local_ts" ] && [ "$dev_ts" -gt 0 ]; then
        echo "  [跳过] $bname (设备版本相同或更新)"
        continue
      fi
    fi

    "$HDC" file send "$t" "$dev_path" 2>/dev/null
    pushed=$((pushed + 1))
  done

  "$HDC" shell "chmod +x $device_dir/*" 2>/dev/null
  echo "  已推送: $pushed 个 $type 测试二进制到 $device_dir"

  local count
  count=$("$HDC" shell "ls $device_dir 2>/dev/null" | tr -d '\r' | wc -l)
  echo "  设备 $device_dir 现有 $count 个文件"
}

# 执行推送
if [ "$TESTS_ONLY" -eq 0 ]; then
  push_libs
fi

if [ "$LIBS_ONLY" -eq 0 ]; then
  if [ "$TEST_TYPE" = "all" ]; then
    for t in unittest moduletest fuzztest benchmark; do
      push_tests_by_type "$t"
    done
  else
    push_tests_by_type "$TEST_TYPE"
  fi
fi

echo ""
echo "=== 推送完成 ==="
if [ "$TEST_TYPE" = "all" ]; then
  echo "下一步: run_module_tests.sh $MODULE --type=unittest (或其他类型)"
else
  echo "下一步: run_module_tests.sh $MODULE --type=$TEST_TYPE"
fi