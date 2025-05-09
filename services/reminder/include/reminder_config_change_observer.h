/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_CONFIG_CHANGE_OBSERVER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_CONFIG_CHANGE_OBSERVER_H

#include "configuration_observer_stub.h"

namespace OHOS {
namespace Notification {
    
/**
 * @brief Listening system language change, when the system language changes,
 *     notify ReminderDataManager.
*/
class ReminderConfigChangeObserver final : public AppExecFwk::ConfigurationObserverStub {
public:
    ReminderConfigChangeObserver() = default;
    ~ReminderConfigChangeObserver() = default;

public:
    void OnConfigurationUpdated(const AppExecFwk::Configuration &configuration) override;

private:
    std::string languageInfo_;
};
} // namespace Notification
} // namespace OHOS

#endif