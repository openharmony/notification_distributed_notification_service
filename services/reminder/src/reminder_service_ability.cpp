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

#include "reminder_service_ability.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t REMINDER_SERVICE_ID = 3204;
REGISTER_SYSTEM_ABILITY_BY_ID(ReminderServiceAbility, REMINDER_SERVICE_ID, false);
}

const std::string EXTENSION_BACKUP = "backup";
const std::string EXTENSION_RESTORE = "restore";
constexpr int64_t INIT_DELAY_TIME = 60 * 1000 * 1000;

ReminderServiceAbility::ReminderServiceAbility(const int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), service_(nullptr)
{}

ReminderServiceAbility::~ReminderServiceAbility()
{}

void ReminderServiceAbility::OnStart()
{
    if (service_ != nullptr) {
        return;
    }

    service_ = ReminderService::GetInstance();
    reminderAgent_ = ReminderDataManager::InitInstance();
    if (!Publish(service_)) {
        return;
    }
    reminderAgent_->Init(true);
    ReminderService::GetInstance()->TryPostDelayUnloadTask(INIT_DELAY_TIME);
}

void ReminderServiceAbility::OnStop()
{
    service_ = nullptr;
    reminderAgent_ = nullptr;
}

}  // namespace Notification
}  // namespace OHOS
