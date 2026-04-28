# OpenHarmony C++完整编码规范

本文档整合OpenHarmony官方编码规范，包含C++风格规范、安全编程指南和32/64位可移植规范。

---

## 目录

1. [命名规范](#命名规范)
2. [格式规范](#格式规范)
3. [注释规范](#注释规范)
4. [头文件规范](#头文件规范)
5. [作用域规范](#作用域规范)
6. [类规范](#类规范)
7. [函数规范](#函数规范)
8. [C++特性规范](#cpp特性规范)
9. [现代C++规范](#现代cpp规范)
10. [安全编程规范](#安全编程规范)
11. [32/64位可移植规范](#3264位可移植规范)
12. [检查清单汇总](#检查清单汇总)

---

## 命名规范

### 通用命名风格

| 类型 | 命名风格 | 示例 |
|------|----------|------|
| 类、结构体、枚举、联合体 | 大驼峰 | `NotificationSlot` |
| 函数(全局、成员) | 大驼峰 | `GetBundleName()` |
| 全局变量 | 小驼峰+g_前缀 | `g_activeConnectCount` |
| 局部变量、参数 | 小驼峰 | `notificationCount` |
| 类成员变量 | 小驼峰+后下划线 | `fileName_` |
| 宏、常量、枚举值 | 全大写+下划线 | `MAX_BUFFER_SIZE` |
| 文件名 | snake_case | `notification_slot.cpp` |

### 文件命名

**规则2.2.1**: C++文件以.cpp结尾，头文件以.h结尾

**规则2.2.2**: 文件名和类名保持一致
```cpp
// 类名: DatabaseConnection
// 文件名: database_connection.h, database_connection.cpp
```

### 全局变量

**规则2.5.1**: 全局变量增加g_前缀
```cpp
int g_activeConnectCount;  // Good

void Func() {
    static int packetCount = 0;  // Good: 函数内静态变量不加前缀
}
```

### 类成员变量

**规则2.5.2**: 类成员变量以小驼峰加后下划线
```cpp
class Foo {
private:
    std::string fileName_;   // Good
    int count_ {0};          // Good
};
```

### 常量和宏

```cpp
// 宏、枚举值: 全大写+下划线
#define MAX(a, b) (((a) < (b)) ? (b) : (a))

enum TintColor {
    RED,
    DARK_RED,
    GREEN
};

// 函数局部常量: 小驼峰
const unsigned int bufferSize = 100;

// 全局常量: 全大写+下划线
namespace Utils {
    const unsigned int DEFAULT_FILE_SIZE_KB = 200;
}
```

---

## 格式规范

### 行宽

**规则3.1.1**: 行宽不超过120字符

**例外**:
- 包含长命令或URL的注释
- 包含长路径的#include语句
- 编译预处理的error信息

### 缩进

**规则3.2.1**: 使用空格缩进，每次4空格，禁止Tab

### 大括号

**规则3.3.1**: 使用K&R风格
```cpp
// 函数左大括号独占一行
int Foo(int a)
{
    if (...) {
        ...
    } else {
        ...
    }
}

// 空函数体可放同一行
class MyClass {
public:
    MyClass() : value_(0) {}
private:
    int value_;
};
```

### if语句

**规则3.6.1**: if语句必须使用大括号
```cpp
// Good
if (objectIsNotExist) {
    return CreateNewObject();
}

// Bad
if (objectIsNotExist)
    return CreateNewObject();
```

**规则3.6.2**: 禁止if/else写在同一行
```cpp
// Good
if (someConditions) {
    DoSomething();
} else {
    ...
}

// Bad
if (someConditions) { ... } else { ... }
```

### 循环语句

**规则3.7.1**: 循环语句必须使用大括号
```cpp
// Good
for (int i = 0; i < someRange; i++) {
    DoSomething();
}

while (condition) { }

// Bad
for (int i = 0; i < someRange; i++)
    DoSomething();
```

### switch语句

**规则3.8.1**: case/default缩进一层
```cpp
switch (var) {
    case 0:             // Good: 缩进
        DoSomething1();
        break;
    case 1: {           // Good: 带大括号
        DoSomething2();
        break;
    }
    default:
        break;
}
```

### 变量声明

**规则3.10.1**: 每行只声明一个变量
```cpp
// Good
int maxCount = 10;
bool isCompleted = false;

// Bad
int maxCount = 10; bool isCompleted = false;
int x, y = 0;
```

### 指针和引用

**建议3.12.1**: `*`靠左或靠右，不要两边都有空格或都没有
```cpp
int* p = nullptr;   // Good
int *p = nullptr;   // Good
int*p = nullptr;    // Bad
int * p = nullptr;  // Bad
```

### 空格规则

**规则3.14.1**: 水平空格规则
- if/switch/for/while关键字后加空格
- 小括号内部两侧不加空格
- 一元操作符后不加空格
- 二元操作符两侧加空格
- 逗号前不加空格，后加空格
- 域操作符(::)前后不加空格

```cpp
void Foo(int b) {  // Good

int i = 0;         // Good

if (condition) {  // Good
    ...
}

for (int i = 0; i < someRange; ++i) {  // Good
    ...
}
```

### 类定义格式

**规则3.15.1**: 访问控制块顺序public/protected/private
```cpp
class MyClass : public BaseClass {
public:
    MyClass();
    void SomeFunction();

private:
    int someVar_;
};
```

---

## 注释规范

### 文件头

**规则3.1**: 文件头必须包含版权许可
```cpp
/*
 * Copyright (c) 2020 XXX
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
```

### 函数注释

**规则4.3.1**: 公有函数必须编写函数头注释
```cpp
/*
 * 返回实际写入的字节数，-1表示写入失败
 * 注意，内存buf由调用者负责释放
 */
int WriteString(const char *buf, int len);
```

**规则4.3.2**: 禁止空有格式的函数头注释
```cpp
// Bad: 空有格式
/*
 * 函数名：WriteString
 * 功能：写入字符串
 * 参数：
 * 返回值：
 */
```

### 代码注释

**规则4.4.1**: 注释放于对应代码上方或右边
**规则4.4.2**: 注释符与内容间1空格
```cpp
// 这是单行注释
DoSomething();

int foo = 100;  // 放右边的注释
```

**规则4.4.3**: 不用的代码直接删除，不要注释掉

---

## 头文件规范

### 头文件职责

**建议5.1.1**: 每个.cpp应有对应.h

### 头文件依赖

**规则5.2.1**: 禁止头文件循环依赖
```cpp
// a.h -> b.h -> c.h -> a.h  // Bad: 循环依赖
```

**规则5.2.2**: 头文件必须使用#define保护
```cpp
#ifndef TIMER_INCLUDE_TIMER_H
#define TIMER_INCLUDE_TIMER_H
...
#endif

// Bad: 不要使用 #pragma once
```

**规则5.2.3**: 禁止extern声明外部函数
```cpp
// Bad
extern int Fun();
void Bar() {
    int i = Fun();
}

// Good
#include "b.h"
void Bar() {
    int i = Fun();
}
```

**规则5.2.4**: 禁止在extern "C"中包含头文件

**建议5.2.1**: 避免前置声明，优先#include

---

## 作用域规范

### 命名空间

**建议6.1.1**: 内部函数/变量使用匿名namespace
```cpp
// Foo.cpp
namespace {
    const int MAX_COUNT = 20;
    void InternalFun() {};
}
```

**规则6.1.1**: 禁止在头文件或#include前using导入命名空间
```cpp
// Bad
using namespace NamespaceB;
#include "b.h"

// Good
#include "b.h"
using namespace NamespaceA;
```

### 全局函数

**建议6.2.1**: 优先使用namespace管理全局函数
```cpp
namespace MyNamespace {
    int Add(int a, int b);
}
```

---

## 类规范

### 构造函数

**规则7.1.1**: 类成员变量必须显式初始化
```cpp
class Message {
public:
    Message() : msgID_(0), msgLength_(0), msgBuffer_(nullptr) {}

private:
    unsigned int msgID_;
    unsigned int msgLength_;
    unsigned char* msgBuffer_;
    std::string someIdentifier_;  // 有默认构造函数，可不显式初始化
};
```

**建议7.1.1**: 优先使用声明时初始化和初始化列表
```cpp
class Message {
private:
    unsigned int msgID_ {0};        // Good: C++11声明时初始化
    unsigned int msgLength_;
};

Message::Message() : msgLength_(0)  // Good: 初始化列表
{
    msgBuffer_ = nullptr;           // Bad: 不推荐函数体内赋值
}
```

**规则7.1.2**: 单参数构造函数声明为explicit
```cpp
class Foo {
public:
    explicit Foo(const string& name) : name_(name) {}  // Good
};
```

### 拷贝/移动控制

**规则7.1.3**: 不需要的拷贝/移动操作明确禁止
```cpp
// 方式1: 继承NoCopyable/NoMovable (推荐)
class Foo : public NoCopyable, public NoMovable {};

// 方式2: =delete
class Foo {
public:
    Foo(const Foo&) = delete;
    Foo& operator=(const Foo&) = delete;
};
```

**规则7.1.4**: 拷贝构造和拷贝赋值成对出现或禁止

**规则7.1.5**: 移动构造和移动赋值成对出现或禁止

---

## 函数规范

### 函数长度

**建议8.1.1**: 函数不超过50行

### 参数

**建议8.2.1**: 参数不超过5个
**建议8.2.2**: 使用引用替代指针
**建议8.2.3**: 避免void*参数

---

## C++特性规范

### 常量

**规则9.1.1**: 禁止用宏定义常量
```cpp
// Bad
#define MAX_SIZE 100

// Good
constexpr int32_t MAX_SIZE = 100;
const int MAX_SIZE = 100;
```

### 类型转换

**规则9.3.1**: 使用C++类型转换
```cpp
// Good
int32_t value = static_cast<int32_t>(doubleValue);
void* ptr = reinterpret_cast<void*>(intPtr);

// Bad
int32_t value = (int32_t)doubleValue;
```

### 资源管理

**规则9.4.1**: 使用RAII管理资源
```cpp
// Good: 使用智能指针
std::unique_ptr<int[]> buffer(new int[100]);
std::shared_ptr<Record> record = std::make_shared<Record>();

// Good: 使用容器
std::vector<int> buffer(100);
```

### new/delete

**规则**: new[]和delete[]配对使用
```cpp
// Good
char* buffer = new char[100];
delete[] buffer;

// Bad
delete buffer;  // 未定义行为
```

---

## 现代C++规范

### nullptr

**规则10.1.3**: 使用nullptr，而非NULL或0
```cpp
// Good
if (ptr != nullptr) {}
ptr = nullptr;

// Bad
if (ptr != NULL) {}
ptr = NULL;
```

### override

**规则10.1.1**: 重写虚函数使用override
```cpp
class Derived : public Base {
public:
    void Foo() override;  // Good
    void Foo();           // Bad: 缺少override
};
```

### =delete

**规则10.1.2**: 使用=delete删除函数
```cpp
class Foo {
public:
    Foo(const Foo&) = delete;
    Foo& operator=(const Foo&) = delete;
};
```

### constexpr

**建议10.3.1**: 使用constexpr定义编译期常量
```cpp
constexpr int32_t MAX_SIZE = 100;
constexpr uint32_t INVALID_VALUE = 0xffffffff;
```

### auto

**建议10.3.2**: auto用于复杂类型，简单类型明确写出
```cpp
// Good: 复杂类型
auto iter = map.find(key);
auto callback = [](int x) { return x * 2; };

// Bad: 简单类型
auto i = 0;          // 应写int
auto count = 100;    // 应写int
```

### Lambda

**规则10.3.2**: 非局部范围禁止按引用捕获
```cpp
// Bad
void Foo() {
    int local = 0;
    threadPool.QueueWork([&] { Process(local); });  // 悬空引用
}

// Good
void Foo() {
    int local = 0;
    threadPool.QueueWork([local] { Process(local); });
}
```

**建议10.3.3**: 避免默认捕获模式
```cpp
// Bad
auto func = [=]() { ... };
auto func = [&]() { ... };

// Good
auto func = [i, this]() { ... };
```

---

## 安全编程规范

### 外部数据校验

**规则**: 对所有外部数据进行合法性校验

外部数据来源：
- 网络、用户输入、命令行、文件
- 环境变量、进程间通信、API参数

校验内容：
- 数据长度、范围、类型和格式
- 只包含可接受字符（白名单）

```cpp
void Foo(const unsigned char* buffer, size_t len)
{
    if (buffer == nullptr || len == 0 || len >= MAX_BUFFER_LEN) {
        return;  // 参数校验
    }
    
    const char* s = reinterpret_cast<const char*>(buffer);
    size_t nameLen = strnlen(s, len);  // 使用strnlen
    if (nameLen == len) {
        return;  // 未找到'\0'
    }
}
```

### 整数溢出

**规则**: 确保有符号整数运算不溢出
**规则**: 确保无符号整数运算不回绕

```cpp
// Good: 先校验再运算
size_t pktLen = ParsePktLen();
if (pktLen > totalLen - readLen) {  // 使用减法避免回绕
    return;
}
```

### 除零错误

**规则**: 确保除法和余数运算除数不为0
```cpp
size_t a = ReadSize();
if (a == 0) {
    return;
}
size_t b = 1000 / a;  // Good: 已确保a不为0
```

### 位运算

**规则**: 只对无符号整数进行位运算
```cpp
// Good
uint32_t data = static_cast<uint32_t>(ReadByte());
uint32_t value = data >> 24;
uint32_t mask = value << data;

// Bad
int32_t data = ReadByte();
int32_t value = data >> 24;  // 有符号右移，实现定义
```

### 内存安全

**规则**: 数组索引校验合法性
```cpp
// Good
if (index >= DEV_NUM) {
    return;
}
devs[index].id = id;

// Bad: 差一错误
if (index > DEV_NUM) {
    return;
}
```

**规则**: 内存申请前校验大小
```cpp
if (size == 0 || size > FOO_MAX_LEN) {
    return;
}
char* buffer = new char[size];
```

**规则**: 释放后立即置nullptr
```cpp
delete msg->body;
msg->body = nullptr;  // Good
```

### 字符串安全

**规则**: 禁止从空指针创建std::string
```cpp
const char* path = std::getenv("PATH");
if (path == nullptr) {
    return;
}
std::string str(path);  // Good
```

**规则**: 确保缓冲区有足够空间
```cpp
char buffer[BUFFER_SIZE];
if (!in.read(buffer, sizeof(buffer))) {
    return;
}
std::string str(buffer, in.gcount());  // Good: 指定长度
```

---

## 32/64位可移植规范

### 数据类型

**规则**: 使用统一定义的数据类型
```cpp
// Good
int8_t, uint8_t, int16_t, uint16_t
int32_t, uint32_t, int64_t, uint64_t

// Bad: 长度可变类型
long, unsigned long  // 32位4字节，64位8字节
```

### 指针存储

**规则**: 用uintptr_t存储指针
```cpp
uintptr_t sessionPtr;
sessionPtr = (uintptr_t)GetMemAddress();  // Good
```

### 格式化输出

**规则**: 64位整数使用PRI宏
```cpp
#include <inttypes.h>

uint64_t a = 0x1234567fffffff;
printf("a = %" PRIx64 "\n", a);  // Good
printf("a = %lx\n", a);          // Bad: 32位不兼容
```

### 常量后缀

**规则**: 禁止L/UL后缀，允许LL/ULL
```cpp
// Good
1, 1U, 1LL, 1ULL

// Bad: 32位/64位长度不同
1L, 1UL
```

### 结构体对齐

**规则**: 禁止硬编码结构体长度
```cpp
// Good
p = (int32_t*)malloc(sizeof(p) * ELEMENTS_NUMBER);

// Bad
p = (int32_t*)malloc(4 * ELEMENTS_NUMBER);  // 假定指针4字节
```

**规则**: 多机通信消息结构体1字节对齐
```cpp
#pragma pack(push)
#pragma pack(1)
struct Message {
    ...
};
#pragma pack(pop)
```

### 类型转换

**规则**: 禁止指针与uint32_t转换
```cpp
// Bad
void* pPkt = (void*)((uint32_t)addr + OFFSET);

// Good
void* pPkt = (void*)((uintptr_t)addr + OFFSET);
```

**规则**: 禁止size_t与int32_t转换
```cpp
// Bad
int32_t length = (int32_t)strlen(str);

// Good
size_t length = strlen(str);
```

---

## 检查清单汇总

### P0 - 严重问题（阻止提交）

**⚠️ 重要：所有安全编码问题必须作为P0级别，阻止提交！**

| 问题 | 检查模式 | 严重性 | 说明 |
|------|----------|--------|------|
| 内存泄漏 | `new[]`无`delete[]` | 阻止 | 动态分配未释放 |
| C风格转换 | `(T*)`/`(T)` | 阻止 | 缺乏类型安全检查 |
| NULL使用 | `\bNULL\b` | 阻止 | 应使用nullptr |
| 空指针解引用 | 无校验直接`->` | 阻止 | 可能导致崩溃 |
| **缺少nullptr校验** | 参数/返回值未校验 | **阻止** | 函数未检查指针有效性 |
| **缺少length校验** | 缓冲区操作未校验 | **阻止** | 可能导致越界访问 |
| **缓冲区操作不安全** | 依赖'\0'终止符 | **阻止** | 未指定长度，可能越界 |
| 整数溢出 | 未校验的算术运算 | 阻止 | 可能导致回绕 |
| 除零 | 未校验的除法 | 阻止 | 可能导致崩溃 |
| 缓冲区溢出 | 未校验的数组访问 | 阻止 | 数组索引越界 |
| 无效内存访问 | 释放后使用 | 阻止 | UAF漏洞 |
| 内存申请无大小校验 | malloc/new前未校验 | 阻止 | 可能申请过大内存 |
| 不安全的字符串操作 | strcpy/sprintf | 阻止 | 应使用安全版本 |
| 外部数据未校验 | 网络/文件输入未验证 | 阻止 | 安全漏洞 |
| length==0未校验 | 允许长度为0的分配 | 阻止 | new char[0]未定义行为 |

**安全编码强制要求：**

1. **所有指针参数必须校验nullptr**
   ```cpp
   void Foo(const char* buffer, size_t len) {
       if (buffer == nullptr || len == 0) {  // 必须校验
           return;
       }
   }
   ```

2. **所有缓冲区操作必须校验长度**
   ```cpp
   bool GetValue(int32_t type, std::string& value) {
       if (iter->second->GetValue() == nullptr || iter->second->GetLength() <= 0) {  // 必须校验
           return false;
       }
       // 使用指定长度，不依赖'\0'
       value = std::string(begin, iter->second->GetLength() - 1);
   }
   ```

3. **所有内存分配前必须校验大小**
   ```cpp
   if (size == 0 || size > MAX_BUFFER_LEN) {  // 必须校验
       return;
   }
   char* buffer = new char[size];
   ```

4. **禁止依赖'\0'终止符确定边界**
   ```cpp
   // Bad: 可能越界
   value = reinterpret_cast<char*>(buffer);  // 依赖'\0'
   
   // Good: 指定长度
   value = std::string(reinterpret_cast<char*>(buffer), length);
   ```

### P1 - 重要问题（修复后合并）

| 问题 | 检查模式 | 严重性 |
|------|----------|--------|
| 重复include | 同头文件多次 | 修复 |
| 缺少header guard | 无`#ifndef` | 修复 |
| 嵌套锁 | 多层`lock_guard` | 修复 |
| 成员未初始化 | 无初始化 | 修复 |
| 行超120字符 | 超长行 | 修复 |
| 缺少override | 虚函数重写无`override` | 修复 |
| 单参数无explicit | 构造函数无`explicit` | 修复 |
| 使用宏常量 | `#define`常量 | 修复 |
| 有符号位运算 | 对int移位 | 修复 |
| long类型使用 | `long`/`unsigned long` | 修复 |
| L/UL后缀 | 常量带`L`/`UL` | 修复 |

### P2 - 风格问题（建议修复）

| 问题 | 检查模式 | 严重性 |
|------|----------|--------|
| const static顺序 | `const static` | 建议 |
| 拼写错误 | 变量名拼写 | 建议 |
| 魔鬼数字 | 未命名常量 | 建议 |
| 缺少函数注释 | public函数无注释 | 建议 |
| 注释掉的代码 | 注释代码块 | 建议 |
| auto滥用 | 简单类型用auto | 建议 |
| lambda默认捕获 | `[=]`/`[&]` | 建议 |
| 行尾空格 | 多余空格 | 建议 |
| Tab缩进 | Tab字符 | 建议 |

---

## 代码示例对照

### Good示例

```cpp
// notification_slot.h
#ifndef BASE_NOTIFICATION_NOTIFICATION_SLOT_H
#define BASE_NOTIFICATION_NOTIFICATION_SLOT_H

#include <cstdint>
#include <string>
#include <memory>

namespace OHOS {
namespace Notification {

class NotificationSlot : public Parcelable {
public:
    explicit NotificationSlot(SlotType type = SlotType::CUSTOM);
    ~NotificationSlot() override;
    
    bool Marshalling(Parcel& parcel) const override;
    
    bool CanEnableLight() const;
    void SetEnableLight(bool isLightEnabled);
    
private:
    std::string id_ {};
    bool isLightEnabled_ {false};
    int32_t lightColor_ {0};
};

}  // namespace Notification
}  // namespace OHOS

#endif
```

### Bad示例（需修复）

```cpp
// 1. 使用NULL
if (ptr != NULL) { }  // 应改为 nullptr

// 2. C风格转换
int value = (int)doubleValue;  // 应改为 static_cast

// 3. 宏定义常量
#define MAX_SIZE 100  // 应改为 constexpr int32_t

// 4. 缺少初始化
int count;  // 应改为 int count {0};

// 5. 缺少override
void Marshalling(Parcel& parcel) const;  // 应加 override

// 6. 长类型未初始化
long value;  // 应改为 int64_t value {0};

// 7. new[]配delete
char* buf = new char[100];
delete buf;  // 应改为 delete[] buf;
```

---

## 检查工具推荐

1. **静态分析**: clang-tidy, cppcheck
2. **编码规范**: cpplint
3. **编译警告**: `-Wall -Wextra -Werror`
4. **地址检测**: AddressSanitizer (ASan)
5. **未定义行为**: UBSan