# Mock Library Reference

This document provides essential mock libraries available for testing in the Distributed Notification Service codebase.

## Mock Library Locations

Mock headers are organized by module in the following locations:

### ANS Service Mocks
- **Location:** `services/ans/test/unittest/mock/include/`
- **Purpose:** Mocks for ANS (Advanced Notification Service) testing

### Reminder Service Mocks
- **Location:** `services/reminder/test/unittest/mock/include/`
- **Purpose:** Mocks for Reminder service testing

### Distributed Service Mocks
- **Location:** `services/distributed/test/unittest/mock/`
- **Purpose:** Mocks for distributed notification testing

### Infrastructure Mocks
- **Location:** `services/infrastructure/test/unittest/mock/include/`
- **Purpose:** Mocks for infrastructure components

### Framework Mocks
- **Location:** `frameworks/core/test/unittest/mock/`
- **Purpose:** Mocks for framework-level testing

## Essential Mock Libraries

### 1. MockBundleManager

**Header:** `mock_bundle_manager_helper.h`

**Purpose:** Mock bundle manager operations for testing bundle-related functionality.

**Available Methods:**
```cpp
namespace OHOS::Notification {
class MockBundleManager {
public:
    static void MockBundleRseult(bool result);
    static void MockSystemBundle(bool systemBundle);
    static void MockClearInstalledBundle();
    static void MockBundleInterfaceResult(const int32_t result);
    static void MockInstallBundle(const NotificationBundleOption& bundleOption);
    static void MockUninstallBundle(const NotificationBundleOption& bundleOption);
};
}
```

**Usage Example:**
```cpp
#include "mock_bundle_manager_helper.h"

HWTEST_F(NotificationTest, BundleCheck_00001, Function | Small)Test | Level1)
{
    MockBundleManager::MockBundleRseult(true);
    MockBundleManager::MockSystemBundle(true);
    
    auto result = notification->CheckBundle();
    EXPECT_EQ(result, true);
}
```

**Use Cases:**
- Testing bundle installation/uninstallation
- Verifying system bundle checks
- Mocking bundle interface results

---

### 2. MockIPCSkeleton

**Header:** `mock_ipc_skeleton.h`

**Purpose:** Mock IPC (Inter-Process Communication) skeleton operations.

**Available Methods:**
```cpp
namespace OHOS {
class IPCSkeleton {
public:
    static bool SetMaxWorkThreadNum(int maxThreadNum);
    static void JoinWorkThread();
    static void StopWorkThread();
    static pid_t GetCallingPid();
    static pid_t GetCallingUid();
    static std::string GetLocalDeviceID();
    static Security::AccessToken::AccessTokenID GetCallingTokenID();
    static std::string GetCallingDeviceID();
    static bool IsLocalCalling();
    static IPCSkeleton &GetInstance();
    static sptr<IRemoteObject> GetContextObject();
};
}
```

**Usage Example:**
```cpp
#include "mock_ipc_skeleton.h"

HWTEST_F(NotificationTest, IPC_00001, Function | Small)Test | Level1)
{
    pid_t testPid = 1234;
    // Mock would set return value
    
    auto pid = IPCSkeleton::GetCallingPid();
    EXPECT_EQ(pid, testPid);
}
```

**Use Cases:**
- Testing IPC-based communication
- Verifying caller identification (PID, UID, TokenID)
- Mocking device ID operations

---

### 3. MockAccessTokenKit

**Header:** `mock_accesstoken_kit.h`

**Purpose:** Mock access token operations for security and permission testing.

**Available Methods:**
```cpp
namespace OHOS::Notification {
void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
void MockDl pType(Security::AccessToken::DlpType mockRet);
void MockApl(Security::AccessToken::ATokenAplEnum mockRet);
void MockIsVerfyPermisson(bool isVerify);
void MockIsSystemApp(const bool isSystemApp);
}
```

**Usage Example:**
```cpp
#include "mock_accesstoken_kit.h"

HWTEST_F(NotificationTest, Permission_00001, Function | Small)Test | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    
    auto result = notification->CheckPermission();
    EXPECT_EQ(result, true);
}
```

**Use Cases:**
- Testing permission verification
- Verifying system app status
- Mocking token type checks

---

### 4. MockSingleKvStore

**Header:** `mock_single_kv_store.h`

**Purpose:** Mock key-value store operations for distributed data testing.

**Available Methods:**
```cpp
namespace OHOS::DistributedKv {
class MockSingleKvStore : public SingleKvStore {
public:
    Status GetEntries(const Key &prefixKey, std::vector<Entry> &entries) const override;
    Status GetEntries(const DataQuery &query, std::vector<Entry> &entries) const override;
    Status GetResultSet(const Key &prefixKey, std::shared_ptr<KvStoreResultSet> &resultSet) const override;
    Status GetResultSet( at &query, std::shared_ptr<KvStoreResultSet> &resultSet) const override;
    Status CloseResultSet(std::shared_ptr<KvStoreResultSet> &resultSet) override;
    Status GetCount( at &query, int &result) const override;
    Status Sync(const std::vector<std::string> &deviceIds, SyncMode mode, uint32_t delayMs) override;
    Status Put(const Key &key, const Value &value) override;
    Status Get(const Key &key, Value &value) override;
    Status Delete(const Key &key) override;
};
}
```

**Usage Example:**
```cpp
#include "mock_single_kv_store.h"

HWTEST_F(NotificationTest, KvStore_00001, Function | Small)Test | Level1)
{
    MockSingleKvStore mockStore;
    std::vector<Entry> entries;
    
    auto status = mockStore.GetEntries("prefix", entries);
    EXPECT_EQ(status, Status::SUCCESS);
}
```

**Use Cases:**
- Testing key-value storage operations
- Verifying data synchronization
- Mocking distributed data access

---

### 5. MockServiceRegistry

**Header:** `mock_service_registry.h`

**Purpose:** Mock service registry operations for system ability testing.

**Available Methods:**
```cpp
namespace OHOS::Notification {
class MockServiceRegistry {
public:
    static void MockGetSystemAbilityManager(const bool ret);
};
}
```

**Usage Example:**
```cpp
#include "mock_service_registry.h"

HWTEST_F(NotificationTest, ServiceRegistry_00001, Function | Small)Test | Level1)
{
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    
    auto result = service->Connect();
    EXPECT_EQ(result, true);
}
```

**Use Cases:**
- Testing service connection/disconnection
- Verifying system ability manager access

---

### 6. MockDataShareHelper

**Header:** `mock_datashare_helper.h`

**Purpose:** Mock data share operations for database access testing.

**Available Methods:**
```cpp
namespace OHOS::Notification {
class MockDataShareHelper : public DataShare::DataShareHelper {
public:
    static void MockCreate(const int32_t ret, const std::shared_ptr<DataShareHelper> helper);
    
    MOCK_METHOD(bool, Release, (), (override));
    MOCK_METHOD(int, Insert, (Uri& uri, const DataShare::DataShareValuesBucket& value), (override));
    MOCK_METHOD(int, Update, (Uri& uri, const DataShare::DataSharePredicates& predicates,
                             const DataShare::DataShareValuesBucket& value), (override));
    MOCK_METHOD(int, Delete, (Uri& uri, const DataShare::DataSharePredicates& predicates), (override));
    MOCK_METHOD(std::shared_ptr<DataShare::DataShareResultSet>, Query,
                (Uri& uri, const DataShare::DataSharePredicates& predicates,
                 std::vector<std::string>& columns, DataShare::DatashareBusinessError* businessError), (override));
};
}
```

**Usage Example:**
```cpp
#include "mock_datashare_helper.h"

HWTEST_F(NotificationTest, DataShare_00001, Function | Small)Test | Level1)
{
    MockDataShareHelper::MockCreate(0, nullptr);
    
    auto result = dataManager->InsertData(uri, value);
    EXPECT_EQ(result, 0);
}
```

**Use Cases:**
- Testing database CRUD operations
- Verifying data query operations
- Mocking data share helper creation

---

### 7. MockOsAccountManager

**Header:** `mock_os_account_manager.h`

**Purpose:** Mock OS account manager operations for multi-user testing.

**Available Methods:**
```cpp
namespace OHOS::Notification {
class MockOsAccountManager {
public:
    static void MockGetForegroundOsAccountLocalId(const int32_t ret);
};
}
```

**Usage Example:**
```cpp
#include "mock_os_account_manager.h"

HWTEST_F(NotificationTest, OsAccount_00001, Function | Small)Test | Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
    
    auto accountId = notification->GetForegroundAccountId();
    EXPECT_EQ(accountId, 100);
}
```

**Use Cases:**
- Testing multi-user scenarios
- Verifying foreground account operations

---

### 8. MockCommonEventManager

**Header:** `mock_common_event_manager.h`

**Purpose:** Mock common event manager operations for event publishing testing.

**Available Methods:**
```cpp
namespace OHOS::Notification {
void MockPublishCommonEventResult(bool result);
}
```

**Usage Example:**
```cpp
#include "mock_common_event_manager.h"

HWTEST_F(NotificationTest, CommonEvent_00001, Function | Small)Test | Level1)
{
    MockPublishCommonEventResult(true);
    
    auto result = notification->PublishEvent(event);
    EXPECT_EQ(result, true);
}
```

**Use Cases:**
- Testing event publishing
- Verifying common event operations

---

## Mock Selection Guidelines

When selecting mocks for your tests:

1. **Identify dependencies** - Check which external services/system abilities your code uses
2. **Choose appropriate mock** - Select mock that matches the dependency
3. **Review available methods** - Check the mock header for available methods
4. **Follow usage patterns** - Look at existing tests for usage examples
5. **Clean up after tests** - Ensure mocks are reset between tests if needed

## Best Practices

1. **Include mock headers** at the top of your test file
2. **Set up mocks** in the test body or SetUp() method
3. **Verify mock behavior** using assertions
4. **Reset mocks** in TearDown() if they maintain state
5. **Use descriptive mock values** to make tests more readable
6. **Document mock setup** in test comments for clarity

## Finding Mock Headers

To find mock headers for specific dependencies:

```bash
# Search for mock headers in the codebase
find . -name "mock_*.h" -path "*/test/unittest/mock/*"

# Search for specific mock
find . -name "mock_bundle_manager.h"
```

## References

- **AGENTS.md:** Project coding guidelines and testing standards
- **TEST_PATTERNS.md:** Common test patterns and examples
- **MOCK_CREATION_GUIDE.md:** Creating new mocks
- **BUILD_CONFIG.md:** BUILD.gn configuration reference
