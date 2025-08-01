/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_COMMON_INCLUDE_DISTRIBUTED_DATA_DEFINE_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_COMMON_INCLUDE_DISTRIBUTED_DATA_DEFINE_H

#include <string>
#include <set>
#include <mutex>
#include <unordered_set>
#include "notification_operation_info.h"

namespace OHOS {
namespace Notification {

namespace {
constexpr const int32_t MIN_DATA_LENGTH = 4;
constexpr char const AnonymousString[] = "******";
constexpr int32_t DEFAULT_REPLY_TIMEOUT = 3;
}

enum BundleListOperationType {
    ADD_BUNDLES = 0,      // add bundles
    REMOVE_BUNDLES,   // remove bundle
    RELEASE_BUNDLES   // release bundles
};

enum DeviceStatueChangeType {
    DEVICE_USING_ONLINE = 0,
    NOTIFICATION_ENABLE_CHANGE = 1,
    ALL_CONNECT_STATUS_CHANGE = 2,
    DEVICE_USING_CLOSE = 3,
};

enum HaOperationType {
    COLLABORATE_DELETE = 0,
    COLLABORATE_REPLY = 1,
    COLLABORATE_JUMP = 2,
};

struct DistributedHaCallbacks {
    std::function<void(int32_t, int32_t, std::string)> hiSysEventCallback;
    std::function<void(int32_t, int32_t, uint32_t, std::string)> haMaintenanceCallback;
    std::function<void(const std::string&, int32_t, int32_t, std::string)> haOperationCallback;
};

struct DeviceStatueChangeInfo {
    int32_t changeType;
    std::string deviceId;
    bool enableChange;
    bool liveViewChange;
};

struct DistributedDeviceConfig {
    int32_t maxTitleLength;
    int32_t maxContentLength;
    uint32_t startAbilityTimeout;
    int32_t operationReplyTimeout = DEFAULT_REPLY_TIMEOUT;
    std::string localType;
    std::set<std::string> supportPeerDevice;
    std::unordered_set<std::string> collaborativeDeleteTypes;
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> collaborativeDeleteTypesByDevice;
};

static std::string StringAnonymous(const std::string& data)
{
    std::string result;
    if (data.length() <= MIN_DATA_LENGTH) {
        result = data + AnonymousString + data;
    } else {
        result = data.substr(0, MIN_DATA_LENGTH) + AnonymousString +
            data.substr(data.length() - MIN_DATA_LENGTH, MIN_DATA_LENGTH);
    }
    return result;
}

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_COMMON_INCLUDE_DISTRIBUTED_DATA_DEFINE_H
