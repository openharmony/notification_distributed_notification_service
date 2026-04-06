# Test Patterns and Examples

This document provides essential test patterns and examples from the Distributed Notification Service
codebase to guide unit test generation.

## Standard Test File Template

```cpp
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#define private public
#define protected public

#include "class_under_test.h"

#include "mock_dependency.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class ClassNameTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// Test cases...

}  // namespace Notification
}  // namespace OHOS
```

## Essential Test Patterns

### Pattern 1: Getter/Setter Tests

**Use Case:** Testing simple getter and setter methods

```cpp
/**
 * @tc.name: GetSlotFlags_00001
 * @tc.desc: Test SetSlotFlags and GetSlotFlags methods
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, GetSlotFlags_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot;
    notificationSlot.SetType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    ASSERT_EQ(notificationSlot.GetId(), "EMERGENCY_INFORMATION");

    notificationSlot.SetSlotFlags(1);
    ASSERT_EQ(notificationSlot.GetSlotFlags(), 1);
}
```

### Pattern 2: String Conversion Tests

**Use Case:** Testing string to enum conversion methods

```cpp
/**
 * @tc.name: GetSlotTypeByString_00001
 * @tc.desc: Test GetSlotTypeByString with valid input
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, GetSlotTypeByString_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType type;
    EXPECT_EQ(NotificationSlot::GetSlotTypeByString(
        NotificationSlot::CONTENT_INFORMATION, type), true);
    EXPECT_EQ(type, NotificationConstant::SlotType::CONTENT_INFORMATION);
}

/**
 * @tc.name: GetSlotTypeByString_00002
 * @tc.desc: Test GetSlotTypeByString with invalid input
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, GetSlotTypeByString_00002, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType type;
    const std::string inputStr = "others";
    EXPECT_EQ(NotificationSlot::GetSlotTypeByString(inputStr, type), false);
}
```

### Pattern 3: Marshalling/Unmarshalling Tests

**Use Case:** Testing IPC serialization/deserialization

```cpp
/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Marshalling and Unmarshalling methods
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot;
    notificationSlot.SetType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    Parcel parcel;
    auto res = notificationSlot.Marshalling(parcel);
    ASSERT_TRUE(res);
    Uri uri("123");
    notificationSlot.SetSound(uri);

    sptr<NotificationSlot> notificationSlotSptr = notificationSlot.Unmarshalling(parcel);
    ASSERT_NE(notificationSlotSptr, nullptr);
    ASSERT_NE(notificationSlotSptr->GetSound().ToString(), "123");
}
```

### Pattern 4: Connection/Disconnection Tests

**Use Case:** Testing service connection and disconnection with mocks

```cpp
/**
 * @tc.name: Connect_00001
 * @tc.desc: Test Connect with null systemAbilityManager
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderBundleManagerHelperTest, Connect_00001, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    bundleManagerHelper->Connect();
}

/**
 * @tc.name: Disconnect_00001
 * @tc.desc: Test Disconnect with connected bundleMgr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderBundleManagerHelperTest, Disconnect_00001, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    bundleManagerHelper->Connect();
    bundleManagerHelper->Disconnect();
}
```

### Pattern 5: Vector/String Operations Tests

**Use Case:** Testing vector and string manipulation methods

```cpp
/**
 * @tc.name: MergeVectorToString_00001
 * @tc.desc: Test MergeVectorToString method
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, MergeVectorToString_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> testVector;
    testVector.push_back("test1");
    testVector.push_back("test2");
    std::string result = NotificationSlot::MergeVectorToString(testVector);
    EXPECT_EQ(result, "test1,test2");
}

/**
 * @tc.name: SplitStringToVector_00001
 * @tc.desc: Test SplitStringToVector method
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, SplitStringToVector_00001, Function | SmallTest | Level1)
{
    std::string testString = "test1,test2,test3";
    std::vector<std::string> result = NotificationSlot::SplitStringToVector(testString);
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "test1");
    EXPECT_EQ(result[1], "test2");
    EXPECT_EQ(result[2], "test3");
}
```

### Pattern 6: Boolean/Conditional Tests

**Use Case:** Testing boolean return values and conditional logic

```cpp
/**
 * @tc.name: IsEnableLight_00001
 * @tc.desc: Test SetEnableLight and IsEnableLight methods
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, IsEnableLight_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot;
    notificationSlot.SetEnableLight(true);
    EXPECT_TRUE(notificationSlot.IsEnableLight());
    
    notificationSlot.SetEnableLight(false);
    EXPECT_FALSE(notificationSlot.IsEnableLight());
}
```

### Pattern 7: Error Handling Tests

**Use Case:** Testing error code handling and failure paths

```cpp
/**
 * @tc.name: MethodWithInvalidInput_00001
 * @tc.desc: Test method with invalid input returns error
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ClassNameTest, MethodWithInvalidInput_00001, Function | SmallTest | Level1)
{
    ClassName className;
    auto result = className.MethodWithInvalidInput("");
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: MethodWithNullPointer_00001
 * @tc.desc: Test method with null pointer returns error
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ClassNameTest, MethodWithNullPointer_00001, Function | SmallTest | Level1)
{
    ClassName className;
    auto result = className.MethodWithNullPointer(nullptr);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}
```

### Pattern 8: Permission/Access Control Tests

**Use Case:** Testing permission verification and access control

```cpp
/**
 * @tc.name: CheckPermission_00001
 * @tc.desc: Test permission check with system app
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, CheckPermission_00001, Function | Small)Test | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    
    auto result = notification->CheckPermission();
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: CheckPermission_00002
 * @tc.desc: Test permission check with non-system app
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, CheckPermission_00002, Function | Small)Test | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    
    auto result = notification->CheckPermission();
    EXPECT_EQ(result, false);
}
```

### Pattern 9: Data Store Operations Tests

**Use Case:** Testing key-value store or database operations

```cpp
/**
 * @tc.name: StoreData_00001
 * @tc.desc: New Test storing data successfully
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DataManagerTest, StoreData_00001, Function | Small)Test | Level1)
{
    DataManager dataManager;
    std::string key = "test_key";
    std::string value = "test_value";
    
    auto result = dataManager.Store(key, value);
    EXPECT_EQ(result, ERR_OK);
    
    std::string retrievedValue;
    auto getResult = dataManager.Get(key, retrievedValue);
    EXPECT_EQ(getResult, ERR_OK);
    EXPECT_EQ(retrievedValue, value);
}

/**
 * @tc.name: StoreData_00002
 * @tc.desc: Test storing data with empty key fails
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DataManagerTest, StoreData_00002, Function | Small)Test | Level1)
{
    DataManager dataManager;
    std::string key = "";
    std::string value = "test_value";
    
    auto result = dataManager.Store(key, value);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}
```

### Pattern 10: Event Publishing Tests

**Use Case:** Testing event publishing and subscription

```cpp
/**
 * @tc.name: PublishEvent_00001
 * @tc.desc: Test publishing common event successfully
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, PublishEvent_00001, Function | Small)Test | Level1)
{
    MockPublishCommonEventResult(true);
    
    CommonEventInfo eventInfo;
    eventInfo.eventName = "TEST_EVENT";
    
    auto result = notification->PublishEvent(eventInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: PublishEvent_00002
 * @tc.desc: Test publishing common event fails
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, PublishEvent_00002, Function | Small)Test | Level1)
{
    MockPublishCommonEventResult(false);
    
    CommonEventInfo eventInfo;
    eventInfo.eventName = "TEST_EVENT";
    
    auto result = notification->PublishEvent(eventInfo);
    EXPECT_NE(result, ERR_OK);
}
```

### Pattern 11: Exception Tests (EXPECT_THROW/EXPECT_NO_THROW)

**Use Case:** Testing void functions or functions that throw exceptions

**Important:** Add `use_exceptions = true` to BUILD.gn when using this pattern

```cpp
/**
 * @tc.name: ProcessWithInvalidParam_00001
 * @tc.desc: Test invalid parameter throws exception
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ProcessorTest, ProcessWithInvalidParam_00001, Function | Small)Test | Level1)
{
    Processor processor;
    
    EXPECT_THROW(processor.Process(""), std::invalid_argument);
}

/**
 * @tc.name: ProcessWithValidInput_00001
 * @tc.desc: Test valid input does not throw exception
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ProcessorTest, ProcessWithValidInput_00001, Function | Small)Test | Level1)
{
    Processor processor;
    std::string validInput = "valid_data";
    
    EXPECT_NO_THROW(processor.Process(validInput));
    EXPECT_TRUE(processor.IsSuccess());
}

/**
 * @tc.name: ConnectWithSuccess_00001
 * @tc.desc: Test successful connection without exception
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ConnectionTest, ConnectWithSuccess_00001, Function | Small)Test | Level1)
{
    Connection connection;
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    
    EXPECT_NO_THROW(connection.Connect());
    EXPECT_TRUE(connection.IsConnected());
}

/**
 * @tc.name: AddItemWithFullContainer_00001
 * @tc.desc: Test adding item to full container throws exception
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ContainerTest, AddItemWithFullContainer_00001, Function | Small)Test | Level1)
{
    Container container(3);
    container.AddItem("item1");
    container.AddItem("item2");
    container.AddItem("item3");
    
    EXPECT_THROW(container.AddItem("item4"), std::overflow_error);
    EXPECT_EQ(container.GetSize(), 3);
}
```

## Test Naming Conventions

### Test Class Names

- Format: `ClassNameTest`
- Examples: `NotificationSlotTest`, `ReminderBundleManagerHelperTest`

### Test Case Names

- Format: `MethodName_ScenarioNumber`
- Examples: `GetSlotFlags_00001`, `Connect_00001`, `PublishEvent_00001`

### Test Documentation

```cpp
/**
 * @tc.name: TestName
 * @tc.desc: Test description
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
```

## Test Levels

- **Level1:** Fast tests (< 1 second)
- **Level2:** Medium tests (1-10 seconds)
- **Level3:** Slow tests (10-60 seconds)
- **Level4:** Very slow tests (> 60 seconds)

## Assertion Guidelines

### Use EXPECT for non-fatal checks

```cpp
EXPECT_EQ(actual, expected);  // Test continues if fails
EXPECT_NE(actual, expected);
EXPECT_TRUE(condition);
EXPECT_FALSE(condition);
EXPECT_PTR_NE(ptr, nullptr);
```

### Use ASSERT for fatal checks

```cpp
ASSERT_EQ(actual, expected);  // Test stops if fails
ASSERT_NE(actual, expected);
ASSERT_TRUE(condition);
ASSERT_FALSE(condition);
ASSERT_PTR_NE(ptr, nullptr);
```

### Common Assertion Patterns

```cpp
// Pointer checks
ASSERT_NE(ptr, nullptr);
EXPECT_EQ(ptr, nullptr);

// Equality checks
EXPECT_EQ(actual, expected);
ASSERT_EQ(actual, expected);

// Boolean checks
EXPECT_TRUE(result);
EXPECT_FALSE(result);

// Size/length checks
EXPECT_EQ(vector.size(), expectedSize);
ASSERT_GT(vector.size(), 0);

// String checks
EXPECT_EQ(str1, str2);
EXPECT_FALSE(str.empty());
```

## Mock Setup Patterns

### Mock in test body

```cpp
HWTEST_F(NotificationTest, TestWithMock_00001, Function | Small)Test | Level1)
{
    MockIsSystemApp(true);
    
    auto result = notification->CheckPermission();
    
    EXPECT_EQ(result, true);
}
```

### Mock in SetUp/TearDown

```cpp
class NotificationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    
    void SetUp() {
        MockIsSystemApp(true);
    }
    
    void TearDown() {
        // Reset mocks if needed
    }
};
```

## Coverage-Driven Test Design

### Achieving 90% Branch Coverage

To achieve 90% branch coverage, ensure tests cover:

1. **All conditional branches:**
   ```cpp
   if (condition) {
       // Test when condition is true
   } else {
       // Test when condition is false
   }
   ```

2. **All loop conditions:**
   ```cpp
   for (int i = 0; i < max; i++) {
       // Test with empty collection
       // Test with single element
       // Test with multiple elements
   }
   ```

3. **All error paths:**
   ```cpp
   if (ptr == nullptr) {
       return ERR_NULL_PTR;  // Test this path
   }
   ```

4. **All boundary conditions:**
   ```cpp
   // Test with minimum value
   // Test with maximum value
   // Test with value just below threshold
   // Test with value just above threshold
   ```

### Coverage Check List

For each function, create tests for:

- [ ] Normal/success path
- [ ] Null pointer checks
- [ ] Empty string/vector checks
- [ ] Invalid input values
- [ ] Boundary conditions (min/max values)
- [ ] Error code paths
- [ ] All if/else branches
- [ ] All loop conditions
- [ ] Exception/error handling

## BUILD.gn Integration

### Adding test to BUILD.gn

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

  # Add this if using EXPECT_THROW/EXPECT_NO_THROW
  use_exceptions = true

  deps = [
    "${frameworks_path}:module_innerkits",
    "${services_path}/module:libmodule",
  ]

  external_deps = [
    "hilog:libhilog",
    "ipc:ipc_core",
  ]

  subsystem_name = "${subsystem_name}"
  part_name = "${component_name}"
}
```

## Best Practices

1. **One assertion per test case** - Keep tests focused
2. **Arrange-Act-Assert pattern** - Organize tests clearly
3. **Descriptive test names** - Make test purpose obvious
4. **Test independence** - Tests should not depend on each other
5. **Appropriate mocking** - Only mock what's necessary
6. **Clean up resources** - Use TearDown for cleanup
7. **Document edge cases** - Add comments for complex scenarios
8. **Maintain test speed** - Use appropriate test levels

## References

- **AGENTS.md:** Project coding guidelines
- **MOCK_REFERENCES.md:** Mock library documentation
- **MOCK_CREATION_GUIDE.md:** Mock creation guide
- **BUILD_CONFIG.md:** BUILD.gn configuration reference
