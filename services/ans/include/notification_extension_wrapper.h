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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_EXT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_EXT_H

#include <string>

#include "errors.h"
#include "nocopyable.h"
#include "notification_request.h"
#include "singleton.h"

namespace OHOS::Notification {
class ExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(ExtensionWrapper);
public:
    DISALLOW_COPY_AND_MOVE(ExtensionWrapper);
    void InitExtentionWrapper();
    typedef void (*SYNC_ADDITION_CONFIG)(const std::string& key, const std::string& value);
    typedef void (*UPDATE_BY_CANCEL)(std::vector<std::string>& hashCodes);
    typedef ErrCode (*GET_UNIFIED_GROUP_INFO)(const sptr<NotificationRequest> &request);

    void SyncAdditionConfig(const std::string& key, const std::string& value);
    void UpdateByCancel(std::vector<std::string>& hashCodes);
    ErrCode GetUnifiedGroupInfo(const sptr<NotificationRequest> &request);

private:
    void* extensionWrapperHandle_ = nullptr;
    SYNC_ADDITION_CONFIG syncAdditionConfig_ = nullptr;
    UPDATE_BY_CANCEL updateByCancel_ = nullptr;
    GET_UNIFIED_GROUP_INFO getUnifiedGroupInfo_ = nullptr;
};

#define EXTENTION_WRAPPER ::OHOS::DelayedSingleton<ExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_EXT_H