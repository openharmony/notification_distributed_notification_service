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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_PREFERENCE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_PREFERENCE_H

#include <unordered_set>

#include "distributed_rdb_helper.h"

namespace OHOS {
namespace Notification {

class DistributedPreferences final {
public:
    DistributedPreferences();
    ~DistributedPreferences() = default;
    /**
     * @brief Get NotificationPreferences instance object.
     */
    static DistributedPreferences& GetInstance();

    int32_t DeleteBundleIcon(const std::string &bundleName);
    int32_t InertBundleIcon(const std::string &bundleName, const std::string &icon);
    int32_t InertBatchBundleIcons(std::unordered_map<std::string, std::string>  &values);
    int32_t GetIconByBundleName(const std::string& bundleName, std::string &icon);
    int32_t GetSavedBundlesIcon(std::vector<std::string>& bundleNames);
    void AddCollaborativeNotification(const std::string &notificationKey);
    bool CheckCollaborativeNotification(const std::string &notificationKey);
private:
    std::mutex preferenceMutex_;
    std::shared_ptr<DistributedRdbHelper> preferncesDB_ = nullptr;
    std::unordered_set<std::string> collaborativeNotificationList_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_PREFERENCE_H
