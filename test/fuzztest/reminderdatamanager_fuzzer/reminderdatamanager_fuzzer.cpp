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

#include "reminder_data_manager.h"
#include "reminder_request_timer.h"
#include "reminderdatamanager_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string bundleName(data);
        int32_t userId = static_cast<int32_t>(GetU32Data(data));
        int32_t uid = static_cast<int32_t>(GetU32Data(data));
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        uint64_t date = static_cast<uint64_t>(GetU32Data(data));
        bool value = static_cast<bool>(GetU32Data(data));
        uint8_t type = static_cast<uint8_t>(GetU32Data(data));

        Notification::ReminderDataManager::InitInstance(nullptr);
        auto manager = Notification::ReminderDataManager::GetInstance();
        manager->Dump();
        manager->CancelAllReminders(bundleName, userId, uid);
        sptr<Notification::NotificationBundleOption> option = new Notification::NotificationBundleOption(
            bundleName, uid);
        manager->CancelReminder(reminderId, option);
        manager->CheckExcludeDateParam(reminderId, option);
        manager->AddExcludeDate(reminderId, date, option);
        manager->DelExcludeDates(reminderId, option);
        std::vector<uint64_t> dates;
        manager->GetExcludeDates(reminderId, option, dates);
        EventFwk::Want want;
        manager->CloseReminder(want, value);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        manager->GetValidReminders(option, reminders);
        manager->Init(value);
        manager->InitUserId();
        std::vector<sptr<Notification::ReminderRequest>> immediatelyReminders;
        std::vector<sptr<Notification::ReminderRequest>> extensionReminders;
        manager->CheckReminderTime(immediatelyReminders, extensionReminders);
        manager->RegisterConfigurationObserver();
        manager->OnUserRemove(userId);
        manager->OnServiceStart();
        manager->OnUserSwitch(userId);
        manager->OnProcessDiedLocked(option);
        manager->RefreshRemindersDueToSysTimeChange(type);

        sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(1200);
        manager->ShouldAlert(reminder);
        manager->ShowActiveReminder(want);
        manager->SnoozeReminder(want);
        manager->StartRecentReminder();
        manager->HandleCustomButtonClick(want);
        manager->ClickReminder(want);
        manager->TerminateAlerting(want);
        AppExecFwk::BundleInfo bundleInfo;
        manager->GetBundleResMgr(bundleInfo);
        manager->UpdateReminderLanguage(reminder);
        manager->UpdateReminderLanguageLocked(reminder);
        manager->OnLanguageChanged();
        manager->OnRemoveAppMgr();
        manager->CancelAllReminders(userId);
        manager->CheckUpdateConditions(reminder, Notification::ReminderRequest::ActionButtonType::INVALID,
            reminder->GetActionButtons());
        manager->AddToShowedReminders(reminder);
        manager->PublishReminder(reminder, option);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
