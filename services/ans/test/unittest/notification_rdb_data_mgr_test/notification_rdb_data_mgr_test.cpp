/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_rdb_data_mgr.h"
#undef private
#undef protected
#include "rdb_store.h"

namespace {
    bool g_mockQueryRet = true;
}

extern void MockHasBlock(bool mockRet);
extern void MockGoToFirstRow(bool mockRet);
extern void MockGetString(bool mockRet);

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace OHOS {
namespace Notification {
class RdbStoreDataCallBackNotificationStorageTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

class RdbStoreTest : public RdbStore {
    public:
        virtual int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int BatchInsert(int64_t &outInsertNum, const std::string &table,
            const std::vector<ValuesBucket> &initialBatchValues)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
            const ValuesBucket &initialValues,
            ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
            const std::string &whereClause = "",
            const std::vector<std::string> &whereArgs = std::vector<std::string>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
            const std::string &whereClause = "", const std::vector<std::string> &whereArgs = std::vector<std::string>(),
            ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause = "",
            const std::vector<std::string> &whereArgs = std::vector<std::string>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual std::unique_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct, const std::string &table,
            const std::vector<std::string> &columns, const std::string &selection = "",
            const std::vector<std::string> &selectionArgs = std::vector<std::string>(), const std::string &groupBy = "",
            const std::string &having = "", const std::string &orderBy = "", const std::string &limit = "")
        {
            return nullptr;
        };
        virtual std::unique_ptr<AbsSharedResultSet> QuerySql(
            const std::string &sql, const std::vector<std::string> &selectionArgs = std::vector<std::string>())
        {
            return nullptr;
        };
        virtual std::unique_ptr<ResultSet> QueryByStep(
            const std::string &sql, const std::vector<std::string> &selectionArgs = std::vector<std::string>())
        {
            return nullptr;
        };
        virtual int ExecuteSql(
            const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
            const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql,
            const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
            const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
            const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>())
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Attach(
            const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey)
        {
            return NativeRdb::E_ERROR;
        };

        virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates)
        {
            return NativeRdb::E_ERROR;
        };
        virtual std::unique_ptr<AbsSharedResultSet> Query(
            const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
        {
            if (g_mockQueryRet == false) {
                std::string name = "aa";
                std::unique_ptr<AbsSharedResultSet> resultSet =
                    std::make_unique<AbsSharedResultSet>(name);
                return resultSet;
            }
            return nullptr;
        };
        virtual std::unique_ptr<ResultSet> QueryByStep(
            const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
        {
            return nullptr;
        };
        virtual std::shared_ptr<ResultSet> RemoteQuery(const std::string &device,
            const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
        {
            return nullptr;
        };
        virtual int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates)
        {
            return NativeRdb::E_ERROR;
        };

        virtual int GetStatus()
        {
            return NativeRdb::E_ERROR;
        };
        virtual void SetStatus(int status) {};
        virtual int GetVersion(int &version)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int SetVersion(int version)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int BeginTransaction()
        {
            return NativeRdb::E_ERROR;
        };
        virtual int RollBack()
        {
            return NativeRdb::E_ERROR;
        };
        virtual int Commit()
        {
            return NativeRdb::E_ERROR;
        };
        virtual bool IsInTransaction()
        {
            return false;
        };
        virtual std::string GetPath()
        {
            return "";
        }
        virtual bool IsHoldingConnection()
        {
            return false;
        };
        virtual bool IsOpen() const
        {
            return false;
        };
        virtual bool IsReadOnly() const
        {
            return false;
        };
        virtual bool IsMemoryRdb() const
        {
            return false;
        };
        virtual int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey)
        {
            return NativeRdb::E_ERROR;
        };
        virtual int ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
            const std::vector<uint8_t> &newKey)
        {
            return NativeRdb::E_ERROR;
        };

        virtual bool SetDistributedTables(const std::vector<std::string>& tables)
        {
            return false;
        };

        virtual std::string ObtainDistributedTableName(const std::string& device, const std::string& table)
        {
            return "";
        }

        virtual bool Sync(const SyncOption& option, const AbsRdbPredicates& predicate, const SyncCallback& callback)
        {
            return false;
        };

        virtual bool Subscribe(const SubscribeOption& option, RdbStoreObserver *observer)
        {
            return false;
        };

        virtual bool UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer)
        {
            return false;
        };

        virtual bool DropDeviceData(const std::vector<std::string>& devices, const DropOption& option)
        {
            return false;
        };
};

/**
 * @tc.name      : RdbStoreDataCallBack_00100
 * @tc.number    :
 * @tc.desc      : test OnOpen function and hasTableInit_ is true
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00100, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<RdbStoreDataCallBackNotificationStorage> rdbStoreData_ =
        std::make_unique<RdbStoreDataCallBackNotificationStorage>(notificationRdbConfig);
    rdbStoreData_->hasTableInit_ = true;
    RdbStoreTest rdbStore;
    EXPECT_EQ(rdbStoreData_->OnOpen(rdbStore), NativeRdb::E_OK);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00200
 * @tc.number    :
 * @tc.desc      : test OnOpen function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00200, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<RdbStoreDataCallBackNotificationStorage> rdbStoreData_ =
        std::make_unique<RdbStoreDataCallBackNotificationStorage>(notificationRdbConfig);
    rdbStoreData_->hasTableInit_ = false;
    RdbStoreTest rdbStore;
    EXPECT_EQ(rdbStoreData_->OnOpen(rdbStore), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00300
 * @tc.number    :
 * @tc.desc      : test Init function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00300, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    EXPECT_EQ(notificationDataMgr->Init(), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00400
 * @tc.number    :
 * @tc.desc      : test Destroy function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00400, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    EXPECT_EQ(notificationDataMgr->Destroy(), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00500
 * @tc.number    :
 * @tc.desc      : test Destroy function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00500, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    EXPECT_EQ(notificationDataMgr->Destroy(), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00600
 * @tc.number    :
 * @tc.desc      : test InsertData function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00600, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(notificationDataMgr->InsertData(key, value), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00700
 * @tc.number    :
 * @tc.desc      : test InsertData function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00700, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(notificationDataMgr->InsertData(key, value), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00800
 * @tc.number    :
 * @tc.desc      : test InsertBatchData function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00800, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::unordered_map<std::string, std::string> values;
    EXPECT_EQ(notificationDataMgr->InsertBatchData(values), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_00900
 * @tc.number    :
 * @tc.desc      : test InsertBatchData function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_00900, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    std::unordered_map<std::string, std::string> values = {
        { "--help", "--help"},
        { "--all", "--all"},
        { "--event", "--event"},
        { "-h", "-h" },
        { "-a", "-a" },
        { "-e", "-e" },
    };
    EXPECT_EQ(notificationDataMgr->InsertBatchData(values), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01000
 * @tc.number    :
 * @tc.desc      : test DeleteData function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01000, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::string key = "<key>";
    EXPECT_EQ(notificationDataMgr->DeleteData(key), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01100
 * @tc.number    :
 * @tc.desc      : test DeleteData function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01100, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    std::string key = "<key>";
    EXPECT_EQ(notificationDataMgr->DeleteData(key), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01200
 * @tc.number    :
 * @tc.desc      : test DeleteBathchData function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01200, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::vector<std::string> keys;
    EXPECT_EQ(notificationDataMgr->DeleteBathchData(keys), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01300
 * @tc.number    :
 * @tc.desc      : test DeleteBathchData function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01300, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    std::vector<std::string> keys;
    std::string key = "<key>";
    keys.emplace_back(key);
    EXPECT_EQ(notificationDataMgr->DeleteBathchData(keys), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01400
 * @tc.number    :
 * @tc.desc      : test QueryData function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01400, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(notificationDataMgr->QueryData(key, value), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01500
 * @tc.number    :
 * @tc.desc      : test QueryData function and absSharedResultSet == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01500, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    std::string key = "<key>";
    std::string value = "<value>";
    g_mockQueryRet = true;
    EXPECT_EQ(notificationDataMgr->QueryData(key, value), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01600
 * @tc.number    :
 * @tc.desc      : test QueryData function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01600, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    std::string key = "<key>";
    std::string value = "<value>";
    g_mockQueryRet = false;
    MockHasBlock(true);
    MockGoToFirstRow(true);
    MockGetString(false);
    EXPECT_EQ(notificationDataMgr->QueryData(key, value), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01700
 * @tc.number    :
 * @tc.desc      : test QueryDataBeginWithKey function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01700, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::string key = "<key>";
    std::unordered_map<std::string, std::string> values;
    EXPECT_EQ(notificationDataMgr->QueryDataBeginWithKey(key, values), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01800
 * @tc.number    :
 * @tc.desc      : test QueryDataBeginWithKey function and absSharedResultSet == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01800, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    g_mockQueryRet = true;
    std::string key = "<key>";
    std::unordered_map<std::string, std::string> values;
    EXPECT_EQ(notificationDataMgr->QueryDataBeginWithKey(key, values), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_01900
 * @tc.number    :
 * @tc.desc      : test QueryDataBeginWithKey function and ret != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_01900, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    g_mockQueryRet = false;
    MockHasBlock(true);
    MockGoToFirstRow(true);
    MockGetString(false);
    std::string key = "<key>";
    std::unordered_map<std::string, std::string> values;
    EXPECT_EQ(notificationDataMgr->QueryDataBeginWithKey(key, values), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_02000
 * @tc.number    :
 * @tc.desc      : test QueryAllData function and rdbStore_ == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_02000, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = nullptr;
    std::unordered_map<std::string, std::string> datas;
    EXPECT_EQ(notificationDataMgr->QueryAllData(datas), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_02100
 * @tc.number    :
 * @tc.desc      : test QueryAllData function and absSharedResultSet == nullptr
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_02100, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    g_mockQueryRet = true;
    std::unordered_map<std::string, std::string> datas;
    EXPECT_EQ(notificationDataMgr->QueryAllData(datas), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_02200
 * @tc.number    :
 * @tc.desc      : test QueryAllData function and GoToFirstRow != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_02200, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    g_mockQueryRet = false;
    MockHasBlock(true);
    MockGoToFirstRow(false);
    std::unordered_map<std::string, std::string> datas;
    EXPECT_EQ(notificationDataMgr->QueryAllData(datas), NativeRdb::E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name      : RdbStoreDataCallBack_02300
 * @tc.number    :
 * @tc.desc      : test QueryAllData function and GetString != NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_02300, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    g_mockQueryRet = false;
    MockHasBlock(true);
    MockGoToFirstRow(true);
    MockGetString(false);
    std::unordered_map<std::string, std::string> datas;
    EXPECT_EQ(notificationDataMgr->QueryAllData(datas), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : RdbStoreDataCallBack_02400
 * @tc.number    :
 * @tc.desc      : test QueryAllData function and GetString == NativeRdb::E_OK
 */
HWTEST_F(RdbStoreDataCallBackNotificationStorageTest, RdbStoreDataCallBack_02400, Function | SmallTest | Level1)
{
    NotificationRdbConfig notificationRdbConfig;
    std::unique_ptr<NotificationDataMgr> notificationDataMgr =
        std::make_unique<NotificationDataMgr>(notificationRdbConfig);
    notificationDataMgr->rdbStore_ = std::make_shared<RdbStoreTest>();
    g_mockQueryRet = false;
    MockHasBlock(true);
    MockGoToFirstRow(true);
    MockGetString(true);
    std::unordered_map<std::string, std::string> datas;
    EXPECT_EQ(notificationDataMgr->QueryAllData(datas), NativeRdb::E_OK);
}
}  // namespace Notification
}  // namespace OHOS
