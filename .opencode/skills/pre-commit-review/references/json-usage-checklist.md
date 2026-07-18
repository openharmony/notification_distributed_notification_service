# nlohmann::json 接口使用安全检视清单

**来源：notification_distributed_notification_service 仓 JSON 转换 cppcrash 排查总结**
**适用范围：本仓所有使用 `nlohmann::json` 的 C++ 代码（`frameworks/`、`services/`、`tools/`）**

> 核心原则：**nlohmann::json 多个接口在类型/存在性不匹配时会抛 C++ 异常（`parse_error` / `type_error` / `out_of_range`），本仓默认不捕获异常，抛出即 cppcrash。所有 JSON 接口调用前必须做前置校验。**

配套文档：仓库根目录 `json_conversion_security_audit.md`（含历史问题清单与修复示例）。

---

## 〇、异常接口速查表（必记）

| 接口 | 抛出异常 | 触发条件 | 安全替代 |
|---|---|---|---|
| `parse(str)`（默认） | `parse_error` | 字符串非合法 JSON | `parse(str, nullptr, false)` 或前置 `json::accept(str)` |
| `at(key)` | `out_of_range` | 键不存在 | 前置 `find(key) != end` 或 `contains(key)` |
| `get<T>()` | `type_error` | 值类型与 `T` 不兼容 | 前置 `is_xxx()`（如 `is_string()`/`is_number_integer()`/`is_boolean()`） |
| `operator[](key)` | `type_error` | 当前值非 object（对 string/number/bool/array 用字符串下标） | 前置 `is_object()`，链式访问逐层校验 |
| `front()/back()` | `out_of_range` | 容器为空 | 前置 `!empty()` |

**已确认不抛异常的接口（无需特殊防护）**：`parse(str, nullptr, false)`（返回 discarded）、`json::accept(str)`、`items()`（对 array/原始类型/null 均安全，空则不迭代）、`contains()`、`find()`、`is_xxx()`、`empty()/size()`、`dump(..., error_handler_t::replace)`。

> ⚠ **纠错声明**：早期版本曾将"`get<int>()` 对 `number_float` 按截断转换不抛异常"列入安全清单，**该说法错误**。nlohmann::json 的 `get<int>()` 对 `number_float` 在值超出 int 表示范围（如 `1e300`）、或为 `NaN`/`Inf` 时会抛 `out_of_range`（exception id 402 "number overflow"）。即使值在范围内，`is_number()`（含 float）后直接 `get<int32_t>()` 仍有崩风险。详见 3.1 节"整数提取的值域校验"。

---

## 一、解析 parse() 安全 - P0

### 1.1 解析前必须校验或使用安全形式

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **禁止裸 parse** | grep `json::parse\(`，确认非 `nullptr, false` 形式时必有不安全的裸调用 | `parse(str)` ❌ | 禁止 `nlohmann::json::parse(str)` 裸调用 |
| **使用安全解析形式** | 人工审查 | `nlohmann::json::parse(str, nullptr, false)` | 必须用 `parse(str, nullptr, false)`，解析失败返回 discarded 而非抛异常 |
| **或前置 accept 校验** | 人工审查 | `if (!json::accept(str)) return; json::parse(str);` | 允许 `accept()` 前置校验后再 parse（有二次解析开销） |
| **解析后校验 discarded** | 人工审查 | `if (jsonObj.is_discarded()) return;` | 用安全形式后，仍需判断 `is_discarded()` |
| **空串校验** | 人工审查 | `if (str.empty()) return;` | parse 前先判空串 |

正确范式：
```cpp
if (str.empty() || !nlohmann::json::accept(str)) { ANS_LOGE("Invalid json"); return; }
nlohmann::json jsonObj = nlohmann::json::parse(str, nullptr, false);
if (jsonObj.is_discarded() || jsonObj.is_null() || !jsonObj.is_object()) { return; }
```

错误范式（曾导致崩溃）：
```cpp
nlohmann::json jsonobj = nlohmann::json::parse(notificationData);  // 应用层不可信输入，崩
```

---

## 二、键访问 at() / operator[] 安全 - P0

### 2.1 at(key) 必须前置存在性校验

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **at 前必须有 find/contains** | 人工审查同一键名 | `if (obj.find(k) != end && obj.at(k).is_xxx())` ✅ | `at(key)` 前必须 `find(key) != end` 或 `contains(key)`，否则键缺失抛 `out_of_range` |
| **public 方法自防御** | 人工审查 | 方法内自带 `contains()` | public/外部可调用方法不得依赖调用方前置校验，必须自带 `contains()` 防御 |

### 2.2 operator[] 链式访问必须逐层校验 is_object()

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **链式 operator[] 逐层校验** | grep `\[.*\]\[` 找链式访问 | `root[A][B]`：先校验 `root[A].is_object()` | `a[b][c]` 链式访问，必须校验 `a[b]` 为 object 后再 `[c]`，否则中间值非 object 抛 `type_error` |
| **operator[] 前确认父为 object** | 人工审查 | 迭代元素先 `is_object()` | 对未知类型 json 用字符串下标前，必须 `is_object()` |

正确范式：
```cpp
if (root.find(KEY_NS) == root.end() || !root[KEY_NS].is_object()) { return; }
auto sub = root[KEY_NS];
if (!sub.contains(KEY_SUB)) { return; }
```

错误范式（曾导致崩溃）：
```cpp
// 仅校验 KEY_NS 存在，未校验 root[KEY_NS] 是否为 object
if (root.find(KEY_NS) == root.end()) { return; }
auto v = root[KEY_NS][KEY_SUB];  // 若 root[KEY_NS] 是 string，抛 type_error
```

---

## 三、类型转换 get<T>() 安全 - P0

### 3.1 标量 get 前必须 is_xxx 校验

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **get<string> 前 is_string** | 人工审查 | `if (at(k).is_string()) x = at(k).get<std::string>();` | 取 string 前必须 `is_string()` |
| **get<int32_t/uint32_t> 前 is_number_integer（+ 值域校验防截断）** | 人工审查 | 见 3.1.1 防御范式 | 取整数前必须 `is_number_integer()`（**禁止用 `is_number()`**：含 float，大浮点/NaN/Inf 取 int 抛 `out_of_range` 崩溃）。`is_number_integer()` 后 `get<int32_t>()` **不崩**，但 int64/uint64 超域值会**静默截断**致值错误，故需值域校验（见 3.1.1 范式 A） |
| **get<int64_t> 前 is_number_integer** | 人工审查 | `if (at(k).is_number_integer()) x = at(k).get<int64_t>();` | 取 int64 前必须 `is_number_integer()`；`get<int64_t>()` 与存储类型 `number_integer` 精确匹配，无值域抛异常风险（最安全） |
| **get<double> 前 is_number** | 人工审查 | `if (at(k).is_number()) x = at(k).get<double>();` | 取浮点前必须 `is_number()` |
| **get<bool> 前 is_boolean** | 人工审查 | `if (at(k).is_boolean()) x = at(k).get<bool>();` | 取 bool 前必须 `is_boolean()` |
| **枚举转换先取 int 再 static_cast** | 人工审查 | 见 3.1.1 | 枚举类型先按 3.1.1 取 int64 + 值域校验，再 `static_cast` |

### 3.1.1 整数提取的值域校验（防 `out_of_range` 与静默截断）⭐

**`get<int32_t>()` 的行为分两种（关键区分：UB vs 实现定义）**：

| 值类型 | `get<int32_t>()` 行为 | 是否崩溃 | 残余风险 |
|---|---|---|---|
| `number_float`（超域/NaN/Inf） | float→int 转换是 **UB**，nlohmann 守卫 → 抛 `out_of_range`(402 "number overflow") | **会崩** | — |
| `number_integer`(int64) 超域 | `static_cast<int32_t>`，整数窄化是**实现定义**（非 UB），库**不守卫** → 静默截断 | **不崩** | 值错误（截断） |
| `number_unsigned`(uint64) 超域 | 同上，`static_cast` 静默截断 | **不崩** | 值错误（截断） |

> 结论：
> - `is_number()`（含 float）后直接 `get<int32_t>()` **会崩**（float 超域/NaN/Inf 抛 `out_of_range`）。
> - **`is_number_integer()` 后 `get<int32_t>()` 不会崩溃**（已排除 float 路径；整数窄化为 `static_cast` 不抛异常）。但超域值会**静默截断**导致值错误（正确性风险，非崩溃）。
> - 若需同时保证"不崩 + 值正确"，用下方范式 A（`get<int64_t>()` 精确匹配 + 手动值域校验后窄化）。

**防御范式 A（推荐：不崩 + 值正确）**：先 `is_number_integer()`，用 `get<int64_t>()`（与存储类型精确匹配、无异常）取出，再手动值域校验后窄化：

```cpp
if (obj.contains(k) && obj.at(k).is_number_integer()) {
    int64_t v = obj.at(k).get<int64_t>();              // 精确匹配，不抛异常
    if (v < INT32_MIN || v > INT32_MAX) {
        ANS_LOGE("integer out of int32 range, skip");
    } else {
        x = static_cast<int32_t>(v);
    }
}
```

**防御范式 B（枚举/uint32 字段）**：

```cpp
if (obj.contains(k) && obj.at(k).is_number_integer()) {
    int64_t v = obj.at(k).get<int64_t>();
    if (v < 0 || v > 0xFFFFFFFFLL) {                   // uint32 域
        ANS_LOGE("out of uint32 range, skip");
    } else {
        x = static_cast<uint32_t>(v);
    }
}
```

**防御范式 C（兜底，不可作主方案）**：`try { x = at(k).get<int32_t>(); } catch (const nlohmann::json::exception&) { ... }`（基类同时覆盖 `type_error`/`out_of_range`）。仅在前置校验缺失的遗留代码过渡使用，新代码必须用范式 A/B。

> 注：本仓既有代码中 `notification_check_info.cpp:134/137/140/143` 等用 `is_number()` 后直接 `get<int32_t>()`，按上述分析属**潜在 cppcrash 风险**（篡改为大浮点/NaN 即崩），应按范式 A 修复。

### 3.2 容器 get<vector<T>> / get<set<T>> 必须校验元素类型（重点）

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **禁止仅 is_array 后 get<vector>** | grep `get<std::vector` / `get<std::set`，回溯上文 | `if (at(k).is_array()) x = at(k).get<vector<string>>();` ❌ | **仅 `is_array()` 不够！** 必须遍历逐元素校验类型后再 get，否则元素类型不匹配抛 `type_error` |
| **遍历逐元素校验** | 人工审查 | 见下方正确范式 | 容器转换必须遍历，逐元素 `is_xxx()` 校验，非法元素跳过 |

正确范式（数组转 vector）：
```cpp
if (obj.find(k) != end && obj.at(k).is_array()) {
    std::vector<std::string> tmp;
    tmp.reserve(obj.at(k).size());
    for (const auto &item : obj.at(k)) {
        if (!item.is_string()) { ANS_LOGE("skip"); continue; }
        tmp.push_back(item.get<std::string>());
    }
    field_ = std::move(tmp);
}
```

正确范式（对象遍历取值）：
```cpp
if (obj.find(k) != end && obj.at(k).is_object()) {
    for (const auto &iter : obj.at(k).items()) {
        if (!iter.value().is_string()) { continue; }
        v.emplace_back(iter.key(), iter.value().get<std::string>());
    }
}
```

错误范式（曾导致崩溃，全仓 18 处）：
```cpp
if (obj.find(k) != end && obj.at(k).is_array()) {
    field_ = obj.at(k).get<std::vector<std::string>>();  // 元素非 string 即崩
}
```

### 3.3 迭代中逐元素 get 必须校验

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **遍历元素 get 前校验类型** | grep `\.value\(\)\.get`、`for.*\.get` | `if (!iter.value().is_string()) continue;` | 在 `for`/`items()` 循环内对每个 value/element 调用 `get<T>()` 前，必须先 `is_xxx()` 校验 |
| **迭代前校验容器类型** | 人工审查 | `if (!arr.is_array()) return;` | 用 `items()` 迭代前确认是 object/array（items 本身不抛，但语义需明确） |

---

## 四、容器边界安全 - P1

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **front/back 前 empty 校验** | grep `\.front\(\)` / `\.back\(\)` | `if (!arr.empty()) x = arr.front();` | `front()/back()` 空容器抛 `out_of_range`，必须前置 `!empty()` |
| **索引访问前 size 校验** | grep `\[i\]` / `\.at(i)` | `if (i < arr.size()) x = arr[i];` | 用整数下标访问前校验 `i < size()` |
| **迭代空容器安全** | 人工审查 | range-for 对空容器安全 | range-for/`items()` 对空容器安全，无需额外校验 |

---

## 五、序列化 dump() 安全 - P2

| 检查项 | 检查方式 | 示例 | 规范要求 |
|---|---|---|---|
| **dump 使用 replace 错误处理** | grep `\.dump\(` | `obj.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)` | `dump` 必须传 `error_handler_t::replace`，避免非法字符触发异常 |

---

## 六、数据来源风险评估 - P0（用于判定修复优先级）

| 数据来源 | 风险 | 说明 |
|---|---|---|
| IPC / 分布式同步对端 / LiveView | 高（不可信） | 可被构造恶意 JSON 主动触发崩溃，必须严格防护 |
| NAPI/ANI 应用层传入字符串 | 高（不可信） | 应用可传任意字符串，parse 必须用安全形式 |
| RDB 持久化 / 解密值 | 中-高 | 跨版本升级/损坏/篡改可能，parse 必须 accept 校验 |
| 系统配置文件 | 中（受控） | 受控输入，仍需 is_object/is_array 防御 |
| 本服务内存构造 | 低 | 自构造可信任，但仍建议统一范式 |

---

## 七、检视快速核对清单（Review Checklist）

代码检视时逐项核对（出现 `nlohmann::json` 用法即过一遍）：

- [ ] 所有 `parse()` 是否用 `nullptr, false` 或前置 `accept()`？无裸 `parse(str)`。
- [ ] 所有 `at(key)` 前是否有 `find(key)` / `contains(key)`？public 方法是否自带防御？
- [ ] 所有 `get<T>()`（标量）前是否有对应 `is_xxx()`？
- [ ] **取 int32/uint32 是否用 `is_number_integer()`（非 `is_number()`）+ `get<int64_t>()` + 值域校验后窄化？**（见 3.1.1：`is_number()` 含 float 会因大浮点/NaN/Inf 抛 `out_of_range` 崩溃；`is_number_integer()` 后不崩但超域静默截断致值错误）
- [ ] 所有 `get<vector<T>>()` / `get<set<T>>()` 是否**遍历逐元素校验**，而非仅 `is_array()` 后直接 get？
- [ ] 遍历中 `iter.value().get<T>()` / `item.get<T>()` 前是否有 `is_xxx()`？
- [ ] 链式 `operator[][]` 是否逐层 `is_object()` 校验？
- [ ] `front()/back()` 前是否 `!empty()`？整数下标前是否 `size()` 校验？
- [ ] `dump()` 是否传 `error_handler_t::replace`？
- [ ] 数据来源为 IPC/分布式/NAPI 不可信输入时，防护是否到位（P0 优先级）？
- [ ] 是否有 `try/catch` 吞异常掩盖问题？（不推荐作为主方案，应改为前置校验）

---

## 八、禁止事项

- 禁止 `nlohmann::json::parse(str)` 裸调用（应用层/外部数据来源）。
- 禁止仅 `is_array()` 后 `get<std::vector<T>>()` / `get<std::set<T>>()` 而不校验元素类型。
- 禁止遍历容器时对元素/值直接 `get<T>()` 而不校验类型。
- 禁止 `at(key)` 不做 `find()`/`contains()` 前置校验（public 方法尤其严格）。
- 禁止链式 `operator[][]` 不校验中间层 `is_object()`。
- 禁止用 `is_number()`（含 float）后直接 `get<int32_t/uint32_t>()`（大浮点/NaN/Inf 抛 `out_of_range` 崩溃）；取窄整数必须 `is_number_integer()` + `get<int64_t>()` + 值域校验。
- 注意：`is_number_integer()` 后 `get<int32_t>()` **不会崩**（整数窄化为 `static_cast` 不抛异常），但 int64/uint64 超域值会**静默截断**致值错误；若需保证值正确，仍须 `get<int64_t>()` + 值域校验后窄化。
- 禁止用 `try/catch` 吞 `nlohmann::json` 异常作为主要防御手段（应前置校验，符合 DFX）。
- 禁止为通过测试而删除 JSON 校验或日志。

---

## 九、推荐：统一工具函数（长期方案）

建议在 `frameworks/core/common` 封装统一 JSON 工具，收敛散落转换逻辑，从源头杜绝复制粘贴引入缺陷：

```cpp
// 示例接口设计
namespace OHOS::Notification::JsonHelper {
    bool ParseSafe(const std::string &s, nlohmann::json &out);  // 内部 nullptr,false + discarded 校验
    bool GetArray(const nlohmann::json &obj, const std::string &key,
                  std::vector<std::string> &out);  // 遍历 + 逐元素 is_string
    bool GetInt(const nlohmann::json &obj, const std::string &key, int32_t &out);  // find + is_number_integer
    bool GetString(const nlohmann::json &obj, const std::string &key, std::string &out);
    bool GetBool(const nlohmann::json &obj, const std::string &key, bool &out);
}
```

数据模型层 `FromJson` 统一改用工具函数，新代码强制走工具函数，旧代码逐步迁移。
