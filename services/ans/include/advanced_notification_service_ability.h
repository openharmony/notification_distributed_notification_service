/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_SERVICE_ABILITY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_SERVICE_ABILITY_H

#include "system_ability.h"

#include "advanced_datashare_observer.h"
#include "advanced_notification_service.h"
#include "system_ability_definition.h"
#include "notification_extension_wrapper.h"

namespace OHOS {
namespace Notification {
class AdvancedNotificationServiceAbility final : public SystemAbility {
public:
    /**
     * @brief The constructor of service ability.
     *
     * @param systemAbilityId Indicates the system ability id.
     * @param runOnCreate Run the system ability on created.
     */
    AdvancedNotificationServiceAbility(const int32_t systemAbilityId, bool runOnCreate);

    /**
     * @brief The deconstructor.
     */
    ~AdvancedNotificationServiceAbility() final;

    DISALLOW_COPY_AND_MOVE(AdvancedNotificationServiceAbility);
    DECLARE_SYSTEM_ABILITY(AdvancedNotificationServiceAbility);

private:
    void OnStart() final;
    void OnStop() final;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnReceiveEvent(const EventFwk::CommonEventData &data);
    int32_t OnExtension(const std::string& extension, MessageParcel& data, MessageParcel& reply) override;

private:
    std::atomic<bool> isDatashaReready_ {false};
    sptr<AdvancedNotificationService> service_;
    std::shared_ptr<SystemEventSubscriber> subscriber_ = nullptr;
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_SERVICE_ABILITY_H
