/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_INTERFACE_SYSTEM_EVENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_INTERFACE_SYSTEM_EVENT_H

#include <functional>
#include <string>

#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {
struct ISystemEvent {
    std::function<void(const sptr<NotificationBundleOption> &)> onBundleRemoved;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    std::function<void()> onScreenOn;
    std::function<void()> onScreenOff;
#endif
    std::function<void(int32_t userId)> onResourceRemove;
    std::function<void(int32_t userId)> OnUserStopped;
    std::function<void(const sptr<NotificationBundleOption> &)> onBundleDataCleared;
    std::function<void(const sptr<NotificationBundleOption> &)> onBundleAdd;
    std::function<void(const sptr<NotificationBundleOption> &)> onBundleUpdate;
    std::function<void()> onBootSystemCompleted;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_INTERFACE_SYSTEM_EVENT_H