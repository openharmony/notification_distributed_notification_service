/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "reminder_helper.h"
#undef private
#undef protected
#include "reminderhelper_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    namespace {
        constexpr uint8_t SLOT_TYPE_NUM = 5;
    }
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        Notification::ReminderRequest reminder;
        reminder.SetContent(stringData);
        reminder.SetExpiredContent(stringData);
        Notification::ReminderHelper::PublishReminder(reminder);
        int32_t reminderId = fdp->ConsumeIntegral<int32_t>();
        Notification::ReminderHelper::CancelReminder(reminderId);
        sptr<Notification::ReminderRequest> valid = new Notification::ReminderRequest();
        std::vector<sptr<Notification::ReminderRequest>> validReminders;
        validReminders.emplace_back(valid);
        Notification::ReminderHelper::GetValidReminders(validReminders);
        Notification::NotificationSlot notificationSlot;
        bool enabled = fdp->ConsumeBool();
        notificationSlot.SetEnableLight(enabled);
        notificationSlot.SetEnableVibration(enabled);
        Notification::ReminderHelper::AddNotificationSlot(notificationSlot);
        uint8_t type = fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        Notification::ReminderHelper::RemoveNotificationSlot(slotType);
        uint64_t excludeDate = static_cast<uint64_t>(reminderId);
        Notification::ReminderHelper::AddExcludeDate(reminderId, excludeDate);
        Notification::ReminderHelper::DelExcludeDates(reminderId);
        std::vector<uint64_t> dates;
        Notification::ReminderHelper::GetExcludeDates(reminderId, dates);
        return Notification::ReminderHelper::CancelAllReminders();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
