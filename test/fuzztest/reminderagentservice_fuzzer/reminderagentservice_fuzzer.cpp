/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "reminder_agent_service.h"
#include "reminder_request_timer.h"
#include "reminderagentservice_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
using namespace Notification;
    bool DoSomethingInterestingWithManager(FuzzedDataProvider* fdp)
    {
        int32_t reminderId = fdp->ConsumeIntegral<int32_t>();
        int64_t date = fdp->ConsumeIntegral<uint64_t>();
        constexpr uint64_t seconds = 1200;
        Notification::ReminderRequest reminder(seconds);
        ReminderAgentService agent;
        int32_t outReminderId = 0;
        agent.PublishReminder(reminder, outReminderId);
        agent.UpdateReminder(reminderId, reminder);
        agent.CancelReminder(reminderId);
        agent.CancelAllReminders();
        agent.CancelReminderOnDisplay(reminderId);
        std::vector<ReminderRequestAdaptation> reminders;
        agent.GetValidReminders(reminders);
        agent.AddExcludeDate(reminderId, date);
        agent.DelExcludeDates(reminderId);
        std::vector<int64_t> dates;
        agent.GetExcludeDates(reminderId, dates);
        agent.RegisterReminderState(nullptr);
        agent.UnRegisterReminderState();
        ReminderAgentService::GetInstance();
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithManager(&fdp);
    return 0;
}
