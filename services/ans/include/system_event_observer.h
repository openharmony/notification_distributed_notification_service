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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_EVENT_OBSERVER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_EVENT_OBSERVER_H

#include <functional>

#include "common_event_subscriber.h"
#include "refbase.h"

#include "interface_system_event.h"
#include "system_event_subscriber.h"

namespace OHOS {
namespace Notification {
class SystemEventObserver {
public:
    /**
     * @brief The constructor.
     *
     * @param callbacks Indicates the ISystemEvent object.
     */
    explicit SystemEventObserver(const ISystemEvent &callbacks);

    /**
     * @brief The deconstructor.
     */
    ~SystemEventObserver();

private:
    void OnReceiveEvent(const EventFwk::CommonEventData &data);
    void OnReceiveEventInner(const EventFwk::CommonEventData &data);
    sptr<NotificationBundleOption> GetBundleOption(AAFwk::Want want);
    sptr<NotificationBundleOption> GetBundleOptionDataCleared(AAFwk::Want want);

    void OnBundleUpdateEventInner(const EventFwk::CommonEventData &data);
    void OnBundleAddEventInner(const EventFwk::CommonEventData &data);
    void OnBootSystemCompletedEventInner(const EventFwk::CommonEventData &data);
private:
    std::shared_ptr<SystemEventSubscriber> subscriber_ = nullptr;
    ISystemEvent callbacks_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_EVENT_OBSERVER_H