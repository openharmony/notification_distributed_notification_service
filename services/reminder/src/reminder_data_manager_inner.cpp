/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_const_define.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "reminder_request_calendar.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "notification_slot.h"
#include "os_account_manager.h"
#include "reminder_event_manager.h"
#include "time_service_client.h"
#include "singleton.h"
#include "locale_config.h"
#include "datashare_predicates_object.h"
#include "datashare_value_object.h"
#include "datashare_helper.h"
#include "data_share_permission.h"
#include "datashare_errno.h"
#include "datashare_template.h"
#include "system_ability_definition.h"
#include "app_mgr_constants.h"
#include "iservice_registry.h"
#include "config_policy_utils.h"
#include "hitrace_meter_adapter.h"
#include "notification_helper.h"
#include "reminder_datashare_helper.h"
#ifdef HAS_HISYSEVENT_PART
#include <sys/statfs.h>
#include "hisysevent.h"
#include "reminder_utils.h"
#include "directory_ex.h"
#endif

namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t ALL_SA_READY_FLAG = 2;  // bundle service and ability service ready.
// The maximum number of applications that can be displayed at a time
constexpr int32_t ONE_HAP_MAX_NUMBER_SHOW_AT_ONCE = 10;
// The maximum number of system that can be displayed at a time
constexpr int32_t TOTAL_MAX_NUMBER_SHOW_AT_ONCE = 500;
// The maximun number of system that can be start extension count
constexpr int32_t TOTAL_MAX_NUMBER_START_EXTENSION = 100;
constexpr int32_t CONNECT_EXTENSION_INTERVAL = 100;
static constexpr const char* USER_SETINGS_DATA_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
static constexpr const char* FOCUS_MODE_ENABLE_URI = "?Proxy=true&key=focus_mode_enable";
static constexpr const char* FOCUS_MODE_ENABLE = "focus_mode_enable";
}

static uint64_t GetRemainPartitionSize(const std::string& partitionName)
{
#ifdef HAS_HISYSEVENT_PART
    struct statfs stat;
    if (statfs(partitionName.c_str(), &stat) != 0) {
        return -1;
    }
    uint64_t blockSize = stat.f_bsize;
    uint64_t freeSize = stat.f_bfree * blockSize;
    constexpr double units = 1024.0;
    return freeSize/(units * units);
#else
    return 0;
#endif
}

static std::vector<uint64_t> GetFileOrFolderSize(const std::vector<std::string>& paths)
{
    std::vector<uint64_t> folderSize;
#ifdef HAS_HISYSEVENT_PART
    for (auto path : paths) {
        folderSize.emplace_back(OHOS::GetFolderSize(path));
    }
#endif
    return folderSize;
}

bool ReminderDataManager::IsSystemReady()
{
    return saReadyFlag_ >= ALL_SA_READY_FLAG;
}

bool ReminderDataManager::IsActionButtonDataShareValid(const sptr<ReminderRequest>& reminder,
    const uint32_t callerTokenId)
{
    auto actionButtonMap = reminder->GetActionButtons();
    for (auto it = actionButtonMap.begin(); it != actionButtonMap.end(); ++it) {
        ReminderRequest::ActionButtonInfo& buttonInfo = it->second;
        if (buttonInfo.dataShareUpdate->uri.empty()) {
            continue;
        }
        Uri uri(buttonInfo.dataShareUpdate->uri);
        auto ret = DataShare::DataSharePermission::VerifyPermission(callerTokenId, uri, false);
        if (ret != DataShare::E_OK) {
            ANSR_LOGE("publish failed, DataSharePermission::VerifyPermission return error[%{public}d],",
                static_cast<int32_t>(ret));
            return false;
        }
    }
    return true;
}

void ReminderDataManager::HandleAutoDeleteReminder(const int32_t notificationId, const int32_t uid,
    const int64_t autoDeletedTime)
{
    ANSR_LOGD("called");
    std::vector<sptr<ReminderRequest>> showedReminder;
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        showedReminder = showedReminderVector_;
    }
    for (auto reminder : showedReminder) {
        if (reminder == nullptr) {
            continue;
        }

        if (reminder->GetUid() != uid || notificationId != reminder->GetNotificationId() ||
            reminder->GetAutoDeletedTime() != autoDeletedTime) {
            continue;
        }
        CloseReminder(reminder, true);
        UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::CLOSE);
        CheckNeedNotifyStatus(reminder, ReminderRequest::ActionButtonType::CLOSE);
    }
    StartRecentReminder();
}

void ReminderDataManager::OnBundleMgrServiceStart()
{
    saReadyFlag_.fetch_add(1);
}

void ReminderDataManager::OnAbilityMgrServiceStart()
{
    saReadyFlag_.fetch_add(1);
}

bool ReminderDataManager::GetCustomRingFileDesc(const sptr<ReminderRequest>& reminder,
    Global::Resource::ResourceManager::RawFileDescriptor& desc)
{
    // obtains the resource manager
    std::lock_guard<std::mutex> locker(resourceMutex_);
    soundResource_ = GetResourceMgr(reminder->GetBundleName(), reminder->GetUid());
    if (soundResource_ == nullptr) {
        ANSR_LOGE("null soundResource");
        return false;
    }
    auto result = soundResource_->GetRawFileDescriptor(reminder->GetCustomRingUri(), desc);
    if (result != Global::Resource::SUCCESS) {
        ANSR_LOGE("GetRawFileDescriptor fail[%{public}d].", static_cast<int32_t>(result));
        return false;
    }
    return true;
}

void ReminderDataManager::CloseCustomRingFileDesc(const int32_t reminderId, const std::string& customRingUri)
{
    std::lock_guard<std::mutex> locker(resourceMutex_);
    if (soundResource_ == nullptr) {
        ANSR_LOGE("null soundResource");
        return;
    }
    auto result = soundResource_->CloseRawFileDescriptor(customRingUri);
    if (result != Global::Resource::SUCCESS) {
        ANSR_LOGE("CloseRawFileDescriptor fail[%{public}d]", static_cast<int32_t>(result));
    }
    ANSR_LOGI("reminderId:[%{public}d]", reminderId);
    soundResource_ = nullptr;
}

void ReminderDataManager::ReportSysEvent(const sptr<ReminderRequest>& reminder)
{
#ifdef HAS_HISYSEVENT_PART
    std::string event = "ALARM_TRIGGER";
    std::string bundleName = reminder->GetBundleName();
    int32_t uid = reminder->GetUid();
    int32_t type = static_cast<int32_t>(reminder->GetReminderType());
    int32_t repeat = static_cast<int32_t>(reminder->IsRepeat());
    uint64_t triggerTime = reminder->GetTriggerTimeInMilli();
    int32_t ringTime = static_cast<int32_t>(reminder->GetRingDuration());
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::NOTIFICATION, event, HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "UID", uid, "NAME", bundleName, "TYPE", type, "REPEAT", repeat, "TRIGGER_TIME", triggerTime,
        "RING_TIME", ringTime);
#endif
}

bool ReminderDataManager::CheckShowLimit(std::unordered_map<std::string, int32_t>& limits, int32_t& totalCount,
    sptr<ReminderRequest>& reminder)
{
    if (totalCount > TOTAL_MAX_NUMBER_SHOW_AT_ONCE) {
        ANSR_LOGE("The maximum number of displays that can be displayed at a time has been reached.");
        return false;
    }
    ++totalCount;
    std::string key = std::to_string(reminder->GetUid()) + "_" + std::to_string(reminder->GetTriggerTimeInMilli());
    auto iter = limits.find(key);
    if (iter == limits.end()) {
        limits[key] = 1;
        return true;
    }
    if (iter->second > ONE_HAP_MAX_NUMBER_SHOW_AT_ONCE) {
        ANSR_LOGE("The maximum number of displays that can be displayed in a single app[%{public}s] has been reached",
            reminder->GetBundleName().c_str());
        return false;
    }
    ++iter->second;
    return true;
}

void ReminderDataManager::OnDataShareInsertOrDelete()
{
    LoadShareReminders();
    std::vector<sptr<ReminderRequest>> immediatelyReminders;
    std::vector<sptr<ReminderRequest>> extensionReminders;
    CheckReminderTime(immediatelyReminders, extensionReminders);
    HandleImmediatelyShow(immediatelyReminders, false);
    StartRecentReminder();
}

void ReminderDataManager::OnDataShareUpdate(const std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    UpdateShareReminders(reminders);
}

void ReminderDataManager::UpdateShareReminders(const std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        if (!(*it)->IsShare() || (*it)->GetReminderType() != ReminderRequest::ReminderType::CALENDAR) {
            continue;
        }
        int32_t reminderId = (*it)->GetReminderId();
        std::string identifier = (*it)->GetIdentifier();
        auto iter = reminders.find(identifier);
        if (iter == reminders.end()) {
            continue;
        }
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>((*it).GetRefPtr());
        calendar->Copy(iter->second);
        if ((*it)->IsShowing()) {
            ShowReminder((*it), false, false, false, false, false);
        }
    }
}

void ReminderDataManager::AsyncStartExtensionAbility(const sptr<ReminderRequest> &reminder, int32_t times,
    const int8_t type, int32_t& count)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        ANSR_LOGE("null manager");
        return;
    }
    if (!manager->IsSystemReady()) {
        ANSR_LOGE("bundle service or ability service not ready.");
        return;
    }
    if (!reminder->IsSystemApp()) {
        ANSR_LOGE("Start extension ability failed, is not system app");
        return;
    }
    if (count > TOTAL_MAX_NUMBER_START_EXTENSION) {
        ANSR_LOGE("The maximum number of start extension has been reached.");
        return;
    }
    ++count;
    times--;
    bool ret = ReminderDataManager::StartExtensionAbility(reminder, type);
    if (!ret && times > 0 && serviceQueue_ != nullptr) {
        ANSR_LOGD("StartExtensionAbilty failed, reminder times: %{public}d", times);
        ffrt::task_attr taskAttr;
        taskAttr.delay(CONNECT_EXTENSION_INTERVAL);
        auto callback = [reminder, times, type]() {
            int32_t count = 0;
            ReminderDataManager::AsyncStartExtensionAbility(reminder, times, type, count);
        };
        serviceQueue_->submit(callback, taskAttr);
    }
}

void ReminderDataManager::UpdateReminderFromDb(const std::vector<sptr<ReminderRequest>>& remindersFromDb)
{
    std::map<int32_t, sptr<ReminderRequest>> reminders;
    for (const auto& reminder : remindersFromDb) {
        reminders[reminder->GetReminderId()] = reminder;
    }
    // Only alerts that do not exist in memory are processed
    for (const auto& reminder : reminderVector_) {
        if (reminder->IsShare()) {
            continue;
        }
        int32_t reminderId = reminder->GetReminderId();
        auto iter = reminders.find(reminderId);
        if (iter != reminders.end()) {
            reminders.erase(iter);
        }
    }
    // new reminder
    for (auto& each : reminders) {
        reminderVector_.push_back(each.second);
    }
}

ErrCode ReminderDataManager::UpdateReminder(const sptr<ReminderRequest>& reminder, const int32_t callingUid)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_OHOS);
    sptr<ReminderRequest> reminderOld = FindReminderRequestLocked(reminder->GetReminderId(), false);
    bool existInMemory = true;
    if (nullptr != reminderOld) {
        if (!CheckIsSameApp(reminderOld, callingUid)) {
            ANSR_LOGW("Not find the reminder due to not match");
            return ERR_REMINDER_NOT_EXIST;
        }
        if (reminderOld->IsShowing()) {
            ANSR_LOGW("Reminder already showing, update reminder failed.");
            return ERR_REMINDER_NOT_EXIST;
        }
    } else {
        existInMemory = false;
        std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
        if (!store_->IsReminderExist(reminder->GetReminderId(), reminder->GetCreatorUid())) {
            ANSR_LOGW("Reminder not find, update reminder failed.");
            return ERR_REMINDER_NOT_EXIST;
        }
    }
    uint32_t callerTokenId = IPCSkeleton::GetCallingTokenID();
    if (callerTokenId == 0) {
        ANSR_LOGE("pushlish failed, callerTokenId is 0");
        return ERR_REMINDER_CALLER_TOKEN_INVALID;
    }
    if (!IsActionButtonDataShareValid(reminder, callerTokenId)) {
        return ERR_REMINDER_DATA_SHARE_PERMISSION_DENIED;
    }

    UpdateAndSaveReminderLocked(reminder, existInMemory);
    queue_->submit([this, reminder]() {
        StartRecentReminder();
    });
    return ERR_OK;
}

void ReminderDataManager::UpdateAndSaveReminderLocked(const sptr<ReminderRequest>& reminder, const bool isInMemory)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    if (reminder->GetTriggerTimeInMilli() == ReminderRequest::INVALID_LONG_LONG_VALUE) {
        ANSR_LOGW("now publish reminder is expired. reminder is =%{public}s", reminder->Dump().c_str());
        reminder->SetExpired(true);
    }
    if (isInMemory) {
        for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
            if (reminder->GetReminderId() == (*it)->GetReminderId() && !(*it)->IsShare()) {
                *it = reminder;
                break;
            }
        }
    } else {
        reminderVector_.push_back(reminder);
    }
    store_->UpdateOrInsert(reminder);
}

void ReminderDataManager::SetActiveReminder(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        // activeReminder_ should not be set with null as it point to actual object.
        activeReminderId_ = -1;
        activeTriggerTime_ = 0;
    } else {
        activeReminderId_ = reminder->GetReminderId();
        activeTriggerTime_ = reminder->GetTriggerTimeInMilli();
        std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
        activeReminder_ = reminder;
    }
    ANSR_LOGD("Set activeReminderId=%{public}d", activeReminderId_.load());
}

void ReminderDataManager::SetAlertingReminder(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        // alertingReminder_ should not be set with null as it point to actual object.
        alertingReminderId_ = -1;
    } else {
        alertingReminderId_ = reminder->GetReminderId();
        alertingReminder_ = reminder;
    }
    ANSR_LOGD("Set alertingReminderId=%{public}d", alertingReminderId_.load());
}

ErrCode ReminderDataManager::CancelReminderToDb(const int32_t reminderId, const int32_t callingUid)
{
    if (store_ == nullptr) {
        ANSR_LOGE("null store");
        return ERR_REMINDER_NOT_EXIST;
    }
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    if (!store_->IsReminderExist(reminderId, callingUid)) {
        ANSR_LOGE("Not find reminder[%{public}d] in db.", reminderId);
        return ERR_REMINDER_NOT_EXIST;
    }
    store_->Delete(reminderId);
    return ERR_OK;
}

bool ReminderDataManager::IsAllowedNotify(const sptr<ReminderRequest> &reminder) const
{
    if (reminder == nullptr) {
        return false;
    }
    bool isAllowed = false;
    NotificationBundleOption bundleOption(reminder->GetBundleName(), reminder->GetUid());
    ErrCode errCode = IN_PROCESS_CALL(NotificationHelper::IsAllowedNotify(bundleOption, isAllowed));
    if (errCode != ERR_OK) {
        ANSR_LOGE("Failed to call IsAllowedNotify, errCode=%{public}d", errCode);
        return false;
    }
    return isAllowed;
}

void ReminderDataManager::ReportTimerEvent(const int64_t targetTime, const bool isSysTimeChanged)
{
#ifdef HAS_HISYSEVENT_PART
    if (targetTime == 0) {
        return;
    }
    constexpr int64_t deviation = 1000 * 60;  // 1min
    int64_t now = GetCurrentTime();
    if ((now - targetTime) <= deviation) {
        return;
    }
    uint8_t errorCode = isSysTimeChanged ? 0 : 1;
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::NOTIFICATION, "REMINDER_TIMER_ERROR",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "TARGET_TIME", targetTime, "TRIGGER_TIME", now, "ERROR_CODE", errorCode);
#endif
}

void ReminderDataManager::ReportUserDataSizeEvent()
{
#ifdef HAS_HISYSEVENT_PART
    std::vector<std::string> paths = {
        "/data/service/el1/public/notification/"
    };
    uint64_t remainPartitionSize = GetRemainPartitionSize("/data");
    std::vector<uint64_t> folderSize = GetFileOrFolderSize(paths);
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "COMPONENT_NAME", "resource_schedule_service",
        "PARTITION_NAME", "/data",
        "REMAIN_PARTITION_SIZE", remainPartitionSize,
        "FILE_OR_FOLDER_PATH", paths,
        "FILE_OR_FOLDER_SIZE", folderSize);
#endif
}

bool ReminderDataManager::CheckSoundConfig(const sptr<ReminderRequest> reminder)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    NotificationBundleOption option;
    option.SetBundleName(reminder->GetBundleName());
    option.SetUid(reminder->GetUid());
    uint32_t slotFlags;
    ErrCode err = NotificationHelper::GetNotificationSlotFlagsAsBundle(option, slotFlags);
    if (err != ERR_OK) {
        ANSR_LOGE("GetNotificationSlotFlagsAsBundle failed.");
        return false;
    }
    if (!(slotFlags & 1)) {
        return false;
    }
    std::string uriStr = USER_SETINGS_DATA_SECURE_URI + std::to_string(reminder->GetUserId())
        + FOCUS_MODE_ENABLE_URI;
    Uri enableUri(uriStr);
    std::string enable;
    bool ret = ReminderDataShareHelper::GetInstance().Query(enableUri, FOCUS_MODE_ENABLE, enable);
    if (!ret) {
        ANSR_LOGE("Query focus mode enable failed.");
        return false;
    }
    if (enable.compare("1") == 0) {
        ANSR_LOGI("Currently not is do not disurb mode.");
        return false;
    }
#endif
    return true;
}

int32_t ReminderDataManager::ConvertRingChannel(ReminderRequest::RingChannel channel)
{
    switch (channel) {
        case ReminderRequest::RingChannel::ALARM:
            return static_cast<int32_t>(AudioStandard::StreamUsage::STREAM_USAGE_ALARM);
        case ReminderRequest::RingChannel::MEDIA:
            return static_cast<int32_t>(AudioStandard::StreamUsage::STREAM_USAGE_MEDIA);
        case ReminderRequest::RingChannel::NOTIFICATION:
            return static_cast<int32_t>(AudioStandard::StreamUsage::STREAM_USAGE_NOTIFICATION);
        default:
            return static_cast<int32_t>(AudioStandard::StreamUsage::STREAM_USAGE_ALARM);
    }
}
}
}
