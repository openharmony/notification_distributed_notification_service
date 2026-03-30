---
name: unittest-coverage
description: Enhance C++ unit test branch coverage to 90%+ through systematic analysis and test generation. Supports gmock for virtual functions and stub symbol override for external functions. Use when improving test coverage, generating missing test cases, mocking external functions or virtual methods, or targeting specific coverage percentages.
---

# Unit Test Coverage Enhancement

## Overview

Enhance C++ unit test branch coverage to >90% through systematic analysis, gap identification, and test generation. Supports gmock for virtual functions and stub symbol override for external functions.

## Workflow

1. **Static Analysis** - Analyze source code and existing test cases to infer coverage
2. **Select Mock Strategy** - Choose gmock or stub based on function type
3. **Generate Tests** - Create test cases for uncovered branches
4. **Verify Coverage** - Build and run tests to verify >90% coverage

## Step 0: Static Analysis

### Run Static Coverage Analysis

Use the static coverage analyzer to analyze source code and existing test cases without running tests:

```bash
python3 scripts/static_coverage_analyzer.py <source-files-or-directories> --test-paths <test-files-or-directories> --output static_coverage_report.json --verbose
```

Example:
```bash
python3 scripts/static_coverage_analyzer.py frameworks/ans/core/ --test-paths test/unittest/ --output static_coverage_report.json --verbose
```

If `--test-paths` is not specified, the analyzer will automatically search for `test/` and `unittest/` directories within the source paths.

### Review Static Analysis Results

The static analysis provides:
- **source_files**: List of analyzed source files
- **test_files**: List of analyzed test files
- **total_branches**: Total number of branches found in source code
- **covered_branches**: Number of branches likely covered by existing tests
- **coverage_percentage**: Estimated coverage percentage
- **branches**: Detailed list of all branches with coverage status
- **test_cases**: Detailed list of all test cases
- **uncovered_branches**: List of branches not covered by any test
- **recommendations**: Prioritized test case recommendations

Example output:
```json
{
  "source_files": ["frameworks/ans/core/notification_slot.cpp"],
  "test_files": ["test/unittest/notification_slot_test.cpp"],
  "total_branches": 25,
  "covered_branches": 18,
  "coverage_percentage": 72.0,
  "uncovered_branches": [
    {
      "file": "frameworks/ans/core/notification_slot.cpp",
      "line": 42,
      "function": "GetSlotType",
      "branch_type": "if",
      "condition": "type == CONTENT_INFORMATION",
      "likely_covered": false,
      "covering_tests": []
    }
  ],
  "recommendations": [
    {
      "file": "frameworks/ans/core/notification_slot.cpp",
      "line": 42,
      "function": "GetSlotType",
      "branch_type": "if",
      "condition": "type == CONTENT_INFORMATION",
      "priority": "high",
      "mock_strategy": "gmock",
      "test_suggestion": "Test condition 'type == CONTENT_INFORMATION' with true/false values"
    }
  ]
}
```

### Static Analysis Limitations

The static analyzer uses heuristics to infer coverage:
- **Accurate for**: Simple conditions, direct mock expectations, explicit input values
- **Less accurate for**: Dynamic values, complex logic, external dependencies, runtime calculations

For accurate coverage, proceed to Step 3 (Verify Coverage) which runs actual tests with instrumentation.

### When to Use Static Analysis vs Runtime Coverage

**Use Static Analysis (Step 0) when:**
- You want a quick estimate of coverage without compiling
- You need to identify obvious gaps in test coverage
- You want to prioritize which branches to test first
- The codebase is large and you want to focus on high-priority gaps

**Use Runtime Coverage (Step 3) when:**
- You need accurate coverage measurements
- You want to verify that tests actually execute the expected branches
- You're preparing for a release or PR review
- Static analysis results are inconclusive

**Recommended Workflow:**
1. Run static analysis to get initial coverage estimate
2. Generate tests for high-priority uncovered branches
3. Run tests with runtime coverage to verify actual coverage
4. Iterate until coverage > 90%

## Step 1: Select Mock Strategy

Focus on high-priority recommendations from static analysis:
- Branches with `mock_strategy: "gmock"` - use gmock
- Branches with `mock_strategy: "stub"` - use stub override
- Loop branches - test empty, single, multiple iterations
- If/else branches - test both true and false paths

## Step 2: Generate Tests

### Use gmock for Virtual Functions

When `mock_strategy: "gmock"`:
- Function is virtual or override
- Member function of a class
- Can be mocked through inheritance

Example gmock setup:
```cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>

class MockNotificationSlot : public NotificationSlot {
public:
    MOCK_METHOD(AnsStatus, GetSlotType, (NotificationConstant::SlotType& type), (override));
    MOCK_METHOD(bool, IsEnableLight, (), (const, override));
};

HWTEST_F(NotificationSlotTest, GetSlotType_WithMock, Function | SmallTest | Level1)
{
    MockNotificationSlot mockSlot;
    NotificationConstant::SlotType type;
    
    EXPECT_CALL(mockSlot, GetSlotType(testing::Ref(type)))
        .WillOnce(testing::Return(AnsStatus()));
    
    auto result = mockSlot.GetSlotType(type);
    EXPECT_EQ(result, ERR_ANS_SUCCESS);
}
```

### Use Stub for External Functions

When `mock_strategy: "stub"`:
- Function is non-member (free function)
- External library function
- Cannot use gmock (not virtual)

Generate stubs:
```bash
python3 scripts/stub_generator.py <source-files> --output-dir test/stubs --verbose
```

Stub usage pattern:
```cpp
#include "stub_external_func.h"

HWTEST_F(MyTest, TestWithExternalStub, Function | SmallTest | Level1)
{
    // Enable stub
    Stub::SetExternalFuncStubEnabled(true);
    
    // Set return value
    Stub::SetExternalFuncReturnValue(expected_value);
    
    // Or set custom callback
    Stub::SetExternalFuncCallback([]() {
        return custom_logic();
    });
    
    // Run test
    auto result = FunctionUnderTest();
    
    // Verify
    EXPECT_EQ(result, expected_value);
    
    // Reset stub
    Stub::ResetExternalFuncStub();
}
```

Link stub with --wrap flag:
```bash
g++ -Wl,--wrap=external_func test.cpp stub_external_func.cpp -o test
```

## Step 3: Verify Coverage

### Test Naming Convention

Follow existing patterns in the codebase:
- Test file: `*_test.cpp`
- Test case: `HWTEST_F(ClassName, FunctionName_ScenarioNumber, Level)`
- Example: `HWTEST_F(NotificationSlotTest, GetSlotType_00001, Function | SmallTest | Level1)`

### Test Structure Template

```cpp
#include <gtest/gtest.h>
#include "target_class.h"

#ifdef USE_GTEST
#define private public
#define protected public
#endif

using namespace testing::ext;

class TargetClassTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: FunctionName_ScenarioNumber
 * @tc.desc: Test description
 * @tc.type: FUNC
 * @tc.require: AR0000000000
 */
HWTEST_F(TargetClassTest, FunctionName_ScenarioNumber, Function | SmallTest | Level1)
{
    // Arrange
    // Setup mocks, stubs, and test data
    
    // Act
    // Call function under test
    
    // Assert
    // Verify results
    EXPECT_EQ(actual, expected);
}
```

### Assertion Requirements

**CRITICAL**: Every test case MUST have at least one assertion or expectation:

- **Value assertions**: `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_GT`, `EXPECT_LT`, etc.
- **Pointer assertions**: `EXPECT_NE(ptr, nullptr)`, `EXPECT_EQ(ptr, expected_ptr)`
- **String assertions**: `EXPECT_STREQ`, `EXPECT_STRNE`
- **Exception assertions**: `EXPECT_NO_THROW()`, `EXPECT_THROW()` (requires `use_exceptions=true`)
- **Mock assertions**: `EXPECT_CALL()`, `EXPECT_TRUE(Mock.VerifyAndClear())`

**Examples of valid assertions**:
```cpp
// Value comparison
EXPECT_EQ(result, expected_value);
EXPECT_TRUE(condition);
EXPECT_FALSE(error_occurred);

// Null pointer check
EXPECT_NE(request, nullptr);
EXPECT_EQ(ptr, expected_ptr);

// Exception handling
EXPECT_NO_THROW(FunctionUnderTest());
EXPECT_THROW(FunctionUnderTest(), std::exception);

// Mock verification
EXPECT_CALL(mock, Method()).WillOnce(Return(value));
auto result = mock.Method();
```

**Examples of INVALID tests (NO ASSERTIONS)**:
```cpp
// ❌ WRONG: No assertions
HWTEST_F(MyTest, TestNoAssertion, Function | SmallTest | Level1)
{
    FunctionUnderTest();
}

// ✅ CORRECT: Has assertion
HWTEST_F(MyTest, TestWithAssertion, Function | SmallTest | Level1)
{
    auto result = FunctionUnderTest();
    EXPECT_EQ(result, expected_value);
}

// ❌ WRONG: Just calling function without verification
HWTEST_F(MyTest, TestNoVerification, Function | SmallTest | Level1)
{
    NotificationAnalyticsUtil::ReportEvent(request);
}

// ✅ CORRECT: Verify no exception thrown (requires use_exceptions=true)
HWTEST_F(MyTest, TestNoThrow, Function | SmallTest | Level1)
{
    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportEvent(request));
}
```

### Branch Coverage Patterns

#### If/Else Branches
```cpp
HWTEST_F(MyTest, FunctionName_BranchTrue, Function | SmallTest | Level1)
{
    // Test true branch
    auto result = FunctionUnderTest(true_condition);
    EXPECT_EQ(result, expected_true);
}

HWTEST_F(MyTest, FunctionName_BranchFalse, Function | SmallTest | Level1)
{
    // Test false branch
    auto result = FunctionUnderTest(false_condition);
    EXPECT_EQ(result, expected_false);
}
```

#### Loop Coverage
```cpp
HWTEST_F(MyTest, FunctionName_LoopEmpty, Function | SmallTest | Level1)
{
    std::vector<int> empty_data;
    auto result = FunctionUnderTest(empty_data);
    EXPECT_EQ(result, expected_empty);
}

HWTEST_F(MyTest, FunctionName_LoopSingle, Function | SmallTest | Level1)
{
    std::vector<int> single_data = {1};
    auto result = FunctionUnderTest(single_data);
    EXPECT_EQ(result, expected_single);
}

HWTEST_F(MyTest, FunctionName_LoopMultiple, Function | SmallTest | Level1)
{
    std::vector<int> multiple_data = {1, 2, 3};
    auto result = FunctionUnderTest(multiple_data);
    EXPECT_EQ(result, expected_multiple);
}
```

#### Switch Coverage
```cpp
HWTEST_F(MyTest, FunctionName_SwitchCase1, Function | SmallTest | Level1)
{
    auto result = FunctionUnderTest(CASE_1);
    EXPECT_EQ(result, expected_case1);
}

HWTEST_F(MyTest, FunctionName_SwitchDefault, Function | SmallTest | Level1)
{
    auto result = FunctionUnderTest(INVALID_CASE);
    EXPECT_EQ(result, expected_default);
}
```

### gmock Patterns

#### Mock Return Values
```cpp
EXPECT_CALL(mock, MethodName())
    .WillOnce(Return(value));
```

#### Mock Multiple Calls
```cpp
EXPECT_CALL(mock, MethodName())
    .Times(2)
    .WillOnce(Return(value1))
    .WillOnce(Return(value2));
```

#### Mock with Parameters
```cpp
EXPECT_CALL(mock, MethodName(param_matcher))
    .WillOnce(Return(value));

// Parameter matchers:
// testing::Eq(value)      - exact match
// testing::Ge(value)      - greater or equal
// testing::Lt(value)      - less than
// testing::_              - any value
// testing::Ref(var)       - reference match
```

#### Mock Side Effects
```cpp
EXPECT_CALL(mock, MethodName())
    .WillOnce(DoAll(
        SetArgReferee<0>(new_value),
        Return(success)
    ));
```

### Stub Patterns

#### Simple Return Value
```cpp
Stub::SetExternalFuncStubEnabled(true);
Stub::SetExternalFuncReturnValue(42);
auto result = FunctionUnderTest();
EXPECT_EQ(result, 42);
Stub::ResetExternalFuncStub();
```

#### Custom Callback
```cpp
Stub::SetExternalFuncStubEnabled(true);
Stub::SetExternalFuncCallback([](int param) {
    return param * 2;
});
auto result = FunctionUnderTest(21);
EXPECT_EQ(result, 42);
Stub::ResetExternalFuncStub();
```

#### Stateful Stub
```cpp
int call_count = 0;
Stub::SetExternalFuncCallback([&]() {
    call_count++;
    return call_count;
});
```

## Step 4: Verify Coverage

### Build Tests

Add test to BUILD.gn:
```gni
ohos_unittest("target_test") {
  sources = [
    "target_test.cpp",
    "stub_external_func.cpp",  # Include stub files
  ]
  
  deps = [
    "//third_party/googletest:gmock",
    "//third_party/googletest:gtest_main",
  ]
  
  external_deps = [
    "hilog:libhilog",
  ]
  
  if (use_stub) {
    cflags = [ "-Wl,--wrap=external_func" ]
  }
  
  # Enable exceptions if using EXPECT_NO_THROW or EXPECT_THROW
  if (use_exceptions) {
    cflags += [ "-fexceptions" ]
  }
}
```

Build:
```bash
./build.sh --product-name rk3568 --build-target target_test --gn-args=use_exceptions=true
```

**IMPORTANT**: Exception assertions (`EXPECT_NO_THROW`, `EXPECT_THROW`) require `use_exceptions=true` to compile. OpenHarmony disables exceptions by default.

### Static Verification

Use static coverage analyzer to verify coverage without running tests:

```bash
python3 scripts/static_coverage_analyzer.py <source-files-or-directories> --test-paths <test-files-or-directories> --output static_coverage_report.json --verbose
```

Example:
```bash
python3 scripts/static_coverage_analyzer.py frameworks/ans/core/ --test-paths test/unittest/ --output static_coverage_report.json --verbose
```

### Review Coverage Results

Check the coverage_percentage in the report:
```json
{
  "total_branches": 25,
  "covered_branches": 23,
  "coverage_percentage": 92.0,
  "uncovered_branches": []
}
```

Target: **Branch coverage > 90%**

### Iterate if Coverage < 90%

If coverage is below 90%:
1. Identify uncovered branches from static_coverage_report.json
2. Generate additional test cases for those branches
3. Rebuild and re-analyze
4. Repeat until >90% achieved

### Optional: Runtime Verification

For accurate coverage verification, you can optionally run tests:

```bash
./out/rk3568/tests/unittest/notification/target_test
```

Or generate detailed coverage report:
```bash
./build.sh --product-name rk3568 --build-target target_test --cc-coverage --gn-args=use_coverage=true
gcov out/rk3568/tests/unittest/notification/target_test.cpp
lcov --capture --directory directory --output-file coverage.info
lcov --summary coverage.info
```

## Best Practices

### Test Organization
- Group related tests in same fixture class
- Use SetUp/TearDown for common initialization
- Keep tests independent and isolated
- One assertion per test case (preferred)

### Assertion Requirements (CRITICAL)
**Every test case MUST have at least one assertion or expectation**

Valid assertions include:
- **Value assertions**: `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_GT`, `EXPECT_LT`, etc.
- **Pointer assertions**: `EXPECT_NE(ptr, nullptr)`, `EXPECT_EQ(ptr, expected_ptr)`
- **String assertions**: `EXPECT_STREQ`, `EXPECT_STRNE`
- **Exception assertions**: `EXPECT_NO_THROW()`, `EXPECT_THROW()`
- **Mock assertions**: `EXPECT_CALL()`, `EXPECT_TRUE(Mock.VerifyAndClear())`

**Examples**:
```cpp
// ✅ CORRECT: Has assertion
HWTEST_F(MyTest, TestWithAssertion, Function | SmallTest | Level1)
{
    auto result = FunctionUnderTest();
    EXPECT_EQ(result, expected_value);
}

// ❌ WRONG: No assertions
HWTEST_F(MyTest, TestNoAssertion, Function | SmallTest | Level1)
{
    FunctionUnderTest();
}

// ✅ CORRECT: Verify no exception thrown (requires use_exceptions=true)
HWTEST_F(MyTest, TestNoThrow, Function | SmallTest | Level1)
{
    EXPECT_NO_THROW(FunctionUnderTest());
}
```

### Mock Selection Guidelines
- **Use gmock when**: Function is virtual, member function, can inherit
- **Use stub when**: External function, free function, C API, non-virtual

### Coverage Quality
- Focus on meaningful branches, not just line coverage
- Test error paths and edge cases
- Mock external dependencies to isolate code under test
- Verify both success and failure scenarios

### Performance
- Run fast tests (Level1) frequently
- Run slow tests (Level2-4) in CI
- Use test fixtures to reduce setup overhead

## Common Issues

### Stub Linking Issues
If stub is not called:
1. Verify --wrap linker flag is set
2. Check function signature matches exactly
3. Ensure stub implementation is linked
4. Use `nm` to verify symbol wrapping

### gmock Compilation Errors
If gmock fails:
1. Ensure function is virtual
2. Check parameter types match exactly
3. Use `MOCK_METHOD` with correct signature
4. Include gmock/gmock.h

### Coverage Not Increasing
If coverage doesn't improve:
1. Verify tests are actually running
2. Check test assertions pass
3. Ensure coverage instrumentation is enabled
4. Rebuild with clean build directory

### Exception Assertion Compilation Errors
If `EXPECT_NO_THROW` or `EXPECT_THROW` fail to compile:
1. OpenHarmony disables exceptions by default
2. Add `use_exceptions=true` to build command: `--gn-args=use_exceptions=true`
3. Add `-fexceptions` to cflags in BUILD.gn if needed
4. Consider using non-exception assertions like `EXPECT_EQ` instead
