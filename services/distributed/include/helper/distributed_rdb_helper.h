/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_RDB_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_RDB_HELPER_H

#include <mutex>
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "notification_constant.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {

struct DistributedRdbConfig {
    std::string dbPath { NotificationConstant::NOTIFICATION_RDB_PATH };
    std::string dbName { NotificationConstant::NOTIFICATION_RDB_NAME };
    std::string tableName { NotificationConstant::NOTIFICATION_RDB_TABLE_NAME };
    std::string journalMode { NotificationConstant::NOTIFICATION_JOURNAL_MODE };
    std::string syncMode { NotificationConstant::NOTIFICATION_SYNC_MODE };
    int32_t version { NotificationConstant::NOTIFICATION_RDB_VERSION };
};

class RdbCallBack : public NativeRdb::RdbOpenCallback {
public:

    RdbCallBack(const DistributedRdbConfig &notificationRdbConfig);

    virtual ~RdbCallBack();

    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

    int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;

    int32_t OnOpen(NativeRdb::RdbStore &rdbStore) override;

    int32_t onCorruption(std::string databaseFile) override;
private:
    DistributedRdbConfig notificationRdbConfig_;
    bool hasTableInit_ = false;
};

class DistributedRdbHelper {
public:

    DistributedRdbHelper(const DistributedRdbConfig &notificationRdbConfig);

    int32_t Init();

    int32_t Destroy();

    /**
     * @brief Insert data in DB.
     * @param key The data Key.
     * @param userId Optional, Indicate which table to insert data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t InsertData(const std::string &key, const std::string &value);

    /**
     * @brief Insert batch data in DB.
     * @param key The data Key.
     * @param userId Optional, Indicate which table to insert data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t InsertBatchData(const std::unordered_map<std::string, std::string> &values);

    /**
     * @brief Delete data in DB.
     * @param key The data Key.
     * @param userId Optional, Indicate which table to delete data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t DeleteData(const std::string &key);

    /**
     * @brief Query data from DB.
     * @param userId Optional, Indicate which table to query data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryData(const std::string &key, std::string &value);

    /**
     * @brief Query data begin whith key in DB.
     * @param userId Optional, Indicate which table to query data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryDataBeginWithKey(const std::string &key, std::unordered_map<std::string, std::string> &values);

private:
    std::vector<std::string> GenerateOperatedTables(const int32_t &userId);
    int32_t DeleteData(const std::string tableName, const std::string key, int32_t &rowId);
    int32_t QueryData(const std::string tableName, const std::string key, std::string &value);
    int32_t QueryData(const std::string tableName, const std::string key, std::vector<uint8_t> &value);
    int32_t QueryDataBeginWithKey(const std::string tableName, const std::string key,
        std::unordered_map<std::string, std::string> &values);
    int32_t QueryAllData(const std::string tableName, std::unordered_map<std::string, std::string> &datas);
    int32_t RestoreForMasterSlaver();

private:
    DistributedRdbConfig notificationRdbConfig_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    mutable ffrt::mutex rdbStorePtrMutex_;
};

}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_RDB_HELPER_H
