# Mock Creation Guide

This document provides a quick guide for creating new mocks in the Distributed Notification Service codebase.

## Mock Types Overview

There are three main mock types in OpenHarmony testing:

1. **Static Function Mocks** - Use static methods to control behavior
2. **Virtual Function Override Mocks** - Inherit and override virtual functions
3. **GMock Macro Mocks** - Use Google Mock's MOCK_METHOD macro

## Type 1: Static Function Mocks

### When to Use

- Need global control of a function's behavior
- Function is a static method without class instance
- Need to set specific return values in tests

### Quick Template

**Header:** `module/test/unittest/mock/include/mock_xxx.h`
```cpp
namespace OHOS::Notification {
class MockClassName {
public:
    static void MockFunctionName(const bool ret);
    static void MockFunctionName(const int32_t ret);
};
}
```

**Implementation:** `module/test/unittest/mock/mock_xxx.cpp`
```cpp
namespace OHOS::Notification {
static bool g_mockFunctionName = false;

void MockClassName::MockFunctionName(const bool ret) {
    g_mockFunctionName = ret;
}
}
```

**Usage in Tests:**
```cpp
#include "mock_xxx.h"

HWTEST_F(ClassNameTest, TestWithMock_00001, Function | Small)Test | Level1)
{
    MockClassName::MockFunctionName(true);
    
    auto result = object->FunctionName();
    EXPECT_EQ(result, true);
}
```

---

## Type 2: Virtual Function Override Mocks

### When to Use

- Need to mock an interface or abstract class
- Class has pure virtual or virtual functions
- Need to provide concrete implementations

### Quick Template

**Header:** `module/test/unittest/mock/include/mock_xxx.h`
```cpp
namespace OHOS {
class MockClassName : public OriginalInterface {
public:
    MockClassName() = default;
    virtual ~MockClassName() = default;

    virtual ReturnType MethodName(ParamType param) override;
    virtual void VoidMethodName(ParamType param) override;
};
}
```

**Implementation:** `module/test/unittest/mock/mock_xxx.cpp`
```cpp
namespace OHOS {
ReturnType MockClassName::MethodName(ParamType param) {
    return DefaultValue;
}

void MockClassName::VoidMethodName(ParamType param) {
    // Execute specific operation or do nothing
}
}
```

**Usage in Tests:**
```cpp
#include "mock_xxx.h"

HWTEST_F(ClassNameTest, TestWithMock_00001, Function | Small)Test | Level1)
{
    MockClassName mockObject;
    
    auto result = mockObject.MethodName(input);
    EXPECT_EQ(result, expectedValue);
}
```

---

## Type 3: GMock Macro Mocks

### When to Use

- Need to verify function call counts and parameters
- Need to set complex expectation behaviors
- Using Google Mock framework

### Quick Template

**Header:** `module/test/unittest/mock/include/mock_xxx.h`
```cpp
#include <gmock/gmock.h>
#include "original_interface.h"

namespace OHOS::Notification {
class MockClassName : public OriginalInterface {
public:
    MockClassName() = default;
    virtual ~MockClassName() = default;

    MOCK_METHOD(ReturnType, MethodName, (ParamType param), (override));
    MOCK_METHOD(void, VoidMethodName, (ParamType param), (override));
};
}
```

**Usage in Tests:**
```cpp
#include "mock_xxx.h"

HWTEST_F(ClassNameTest, TestWithMock_00001, Function | Small)Test | Level1)
{
    MockClassName mockObject;
    
    // Set expectation
    EXPECT_CALL(mockObject, MethodName(testing::_))
        .Times(1)
        .WillOnce(testing::Return(expectedValue));
    
    auto result = mockObject.MethodName(input);
    EXPECT_EQ(result, expectedValue);
}
```

---

## Mocking Pure Virtual Functions

Pure virtual functions must be overridden. Use virtual function override mocks or GMock macro mocks:

```cpp
class MockInterface : public OriginalInterface {
public:
    MOCK_METHOD(ReturnType, PureVirtualMethod, (ParamType param), (override));
};
```

---

## BUILD.gn Integration

### Update Mock's BUILD.gn

**File:** `module/test/unittest/mock/BUILD.gn`
```gn
ohos_source_set("mock_source") {
  sources = [
    "mock_xxx.cpp",
  ]

  include_dirs = [
    "include",
  ]
}
```

### Update Test's BUILD.gn

**File:** `module/test/unittest/BUILD.gn`
```gn
ohos_unittest("test_name") {
  module_out_path = module_output_path

  include_dirs = [
    ".",
    "include",
    "/${services_path}/module/include",
    "${services_path}/module/test/unittest/mock/include",
  ]

  sources = [
    "test_file.cpp",
  ]

  cflags = [
    "-Dprivate=public",
    "-Dprotected=public",
  ]

  deps = [
    "${frameworks_path}:module_innerkits",
    "${services_path}/module:libmodule",
    "${services_path}/module/test/unittest/mock:mock_source",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"
}
```

---

## Best Practices

### Naming Conventions

- Mock header files: `mock_xxx.h`
- Mock implementation files: `mock_xxx.cpp`
- Mock class names: `MockClassName`

### Header Guards

Use unique macro names:
```cpp
#ifndef MOCK_XXX_H
#define MOCK_XXX_H

// Content

#endif  // MOCK_XXX_H
```

### Copyright Headers

All mock files should include copyright header:
```cpp
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * ...
 */
```

### Minimal Mocking

Only mock necessary methods, avoid over-mocking:
```cpp
// Good practice: only mock needed methods
MOCK_METHOD(int, NeededMethod, (int param), (override));

// Bad practice: mock all methods
MOCK_METHOD(int, Method1, (...), (override));
MOCK_METHOD(int, Method2, (...), (override));
// ... many unneeded methods
```

### Document Mocks

Add comments explaining mock purpose in header:
```cpp
/**
 * @brief Mock for DataShareHelper to test database operations
 * 
 * This mock provides control over database operations for unit testing.
 * Use MockCreate() to control helper creation behavior.
 */
class MockDataShareHelper : public DataShare::DataShareHelper {
    // ...
};
```

### Clean Up Mocks

If mocks maintain state, ensure cleanup between tests:
```cpp
class MockClassName {
public:
    static void Reset() {
        g_mockState = defaultValue;
    }
};

// In tests
HWTEST_F(ClassNameTest, Test_00001, Function | Small)Test | Level1)
{
    MockClassName::Reset();  // Clean up state
    // Test code
}
```

---

## Common Issues

### Q: How to mock pure virtual functions?

A: Pure virtual functions must be overridden. Use virtual function override mocks or GMock macro mocks:
```cpp
class MockInterface : public OriginalInterface {
public:
    MOCK_METHOD(ReturnType, PureVirtualMethod, (ParamType param), (override));
};
```

### Q: How to mock constructors?

A: Use factory pattern or dependency injection:
```cpp
// Bad practice: direct construction
auto obj = new ClassName();  // Hard to mock

// Good practice: use factory
auto obj = factory->Create();  // Can mock factory
```

### Q: How to handle mock destructors?

A: If mocks need special cleanup, override destructor:
```cpp
class MockClassName : public OriginalInterface {
public:
    ~MockClassName() override {
        // Cleanup logic
    }
};
```

---

## References

- **AGENTS.md:** Project coding guidelines
- **MOCK_REFERENCES.md:** Existing mock library documentation
- **TEST_PATTERNS.md:** Test patterns and examples
- **BUILD_CONFIG.md:** BUILD.gn configuration reference
