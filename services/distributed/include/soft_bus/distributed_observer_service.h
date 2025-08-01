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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_OBSERVER_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_OBSERVER_SERVICE_H

#include "common_event_subscriber.h"
#ifdef SCREENLOCK_MGR_ENABLE
#include "screenlock_manager.h"
#endif

#include <memory>

namespace OHOS {
namespace Notification {

class DistributedEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    DistributedEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo)
    {}

    ~DistributedEventSubscriber()
    {}
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

class OberverService {
public:
    static OberverService& GetInstance();
    int32_t IsScreenLocked();
    void Destory();
#ifdef SCREENLOCK_MGR_ENABLE
    int32_t Unlock(const ScreenLock::Action &action, const sptr<ScreenLock::ScreenLockCallbackInterface> &listener);
#endif
    void Init(uint16_t deviceType);
private:
    OberverService() = default;
    ~OberverService() = default;
    std::shared_ptr<DistributedEventSubscriber> subscriber_ = nullptr;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_OBSERVER_SERVICE_H
