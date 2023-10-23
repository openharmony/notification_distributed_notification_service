/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "reminder_request.h"

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "locale_config.h"
#include "os_account_manager.h"
#include "reminder_store.h"
#include "system_ability_definition.h"
#include "want_agent_helper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {
namespace {
const int32_t BASE_YEAR = 1900;
const int32_t SINGLE_BUTTON_INVALID = 0;
const int32_t SINGLE_BUTTON_JSONSTRING = 0;
const int32_t SINGLE_BUTTON_ONLY_ONE = 1;
const int32_t SINGLE_BUTTON_MIN_LEN = 2;
const int32_t SINGLE_BUTTON_MAX_LEN = 4;
const int32_t BUTTON_TYPE_INDEX = 0;
const int32_t BUTTON_TITLE_INDEX = 1;
const int32_t BUTTON_PKG_INDEX = 2;
const int32_t BUTTON_ABILITY_INDEX = 3;
}

int32_t ReminderRequest::GLOBAL_ID = 0;
const uint64_t ReminderRequest::INVALID_LONG_LONG_VALUE = 0;
const uint16_t ReminderRequest::INVALID_U16_VALUE = 0;
const uint16_t ReminderRequest::MILLI_SECONDS = 1000;
const uint16_t ReminderRequest::SAME_TIME_DISTINGUISH_MILLISECONDS = 1000;
const uint32_t ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI = 5 * 60 * 1000;
const uint8_t ReminderRequest::INVALID_U8_VALUE = 0;
const uint8_t ReminderRequest::REMINDER_STATUS_INACTIVE = 0;
const uint8_t ReminderRequest::REMINDER_STATUS_ACTIVE = 1;
const uint8_t ReminderRequest::REMINDER_STATUS_ALERTING = 2;
const uint8_t ReminderRequest::REMINDER_STATUS_SHOWING = 4;
const uint8_t ReminderRequest::REMINDER_STATUS_SNOOZE = 8;
const uint8_t ReminderRequest::TIME_HOUR_OFFSET = 12;
const std::string ReminderRequest::NOTIFICATION_LABEL = "REMINDER_AGENT";
const std::string ReminderRequest::REMINDER_EVENT_ALARM_ALERT = "ohos.event.notification.reminder.ALARM_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_CLOSE_ALERT = "ohos.event.notification.reminder.CLOSE_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT = "ohos.event.notification.reminder.SNOOZE_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT = "ohos.event.notification.reminder.COSTUM_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT = "ohos.event.notification.reminder.ALERT_TIMEOUT";
const std::string ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION =
    "ohos.event.notification.reminder.REMOVE_NOTIFICATION";
const std::string ReminderRequest::PARAM_REMINDER_ID = "REMINDER_ID";
const std::string ReminderRequest::SEP_BUTTON_SINGLE = "<SEP,/>";
const std::string ReminderRequest::SEP_BUTTON_MULTI = "<SEP#/>";
const std::string ReminderRequest::SEP_WANT_AGENT = "<SEP#/>";
const int32_t ReminderRequest::SUNDAY = 7;

// For database recovery.
const std::string ReminderRequest::REMINDER_ID = "reminder_id";
const std::string ReminderRequest::PKG_NAME = "package_name";
const std::string ReminderRequest::USER_ID = "user_id";
const std::string ReminderRequest::UID = "uid";
const std::string ReminderRequest::SYS_APP = "system_app";
const std::string ReminderRequest::APP_LABEL = "app_label";
const std::string ReminderRequest::REMINDER_TYPE = "reminder_type";
const std::string ReminderRequest::REMINDER_TIME = "reminder_time";
const std::string ReminderRequest::TRIGGER_TIME = "trigger_time";
const std::string ReminderRequest::RTC_TRIGGER_TIME = "rtc_trigger_time";
const std::string ReminderRequest::TIME_INTERVAL = "time_interval";
const std::string ReminderRequest::SNOOZE_TIMES = "snooze_times";
const std::string ReminderRequest::DYNAMIC_SNOOZE_TIMES = "dynamic_snooze_times";
const std::string ReminderRequest::RING_DURATION = "ring_duration";
const std::string ReminderRequest::IS_EXPIRED = "is_expired";
const std::string ReminderRequest::IS_ACTIVE = "is_active";
const std::string ReminderRequest::STATE = "state";
const std::string ReminderRequest::ZONE_ID = "zone_id";
const std::string ReminderRequest::HAS_SCHEDULED_TIMEOUT = "has_ScheduledTimeout";
const std::string ReminderRequest::ACTION_BUTTON_INFO = "button_info";
const std::string ReminderRequest::CUSTOM_BUTTON_URI = "custom_button_uri";
const std::string ReminderRequest::SLOT_ID = "slot_id";
const std::string ReminderRequest::NOTIFICATION_ID = "notification_id";
const std::string ReminderRequest::TITLE = "title";
const std::string ReminderRequest::CONTENT = "content";
const std::string ReminderRequest::SNOOZE_CONTENT = "snooze_content";
const std::string ReminderRequest::EXPIRED_CONTENT = "expired_content";
const std::string ReminderRequest::AGENT = "agent";
const std::string ReminderRequest::MAX_SCREEN_AGENT = "maxScreen_agent";
const std::string ReminderRequest::TAP_DISMISSED = "tapDismissed";
const std::string ReminderRequest::AUTO_DELETED_TIME = "autoDeletedTime";

std::string ReminderRequest::sqlOfAddColumns = "";
std::vector<std::string> ReminderRequest::columns;

ReminderRequest::ReminderRequest()
{
    InitServerObj();
}

ReminderRequest::ReminderRequest(const ReminderRequest &other)
{
    this->content_ = other.content_;
    this->expiredContent_ = other.expiredContent_;
    this->snoozeContent_ = other.snoozeContent_;
    this->displayContent_ = other.displayContent_;
    this->title_ = other.title_;
    this->isExpired_ = other.isExpired_;
    this->isSystemApp_ = other.isSystemApp_;
    this->snoozeTimes_ = other.snoozeTimes_;
    this->snoozeTimesDynamic_ = other.snoozeTimesDynamic_;
    this->state_ = other.state_;
    this->notificationId_ = other.notificationId_;
    this->reminderId_ = other.reminderId_;
    this->reminderTimeInMilli_ = other.reminderTimeInMilli_;
    this->ringDurationInMilli_ = other.ringDurationInMilli_;
    this->triggerTimeInMilli_ = other.triggerTimeInMilli_;
    this->timeIntervalInMilli_ = other.timeIntervalInMilli_;
    this->reminderType_ = other.reminderType_;
    this->slotType_ = other.slotType_;
    this->notificationRequest_ = other.notificationRequest_;
    this->wantAgentInfo_ = other.wantAgentInfo_;
    this->maxScreenWantAgentInfo_ = other.maxScreenWantAgentInfo_;
    this->actionButtonMap_ = other.actionButtonMap_;
    this->tapDismissed_= other.tapDismissed_;
    this->autoDeletedTime_ = other.autoDeletedTime_;
    this->customButtonUri_ = other.customButtonUri_;
}

ReminderRequest::ReminderRequest(int32_t reminderId)
{
    reminderId_ = reminderId;
    InitServerObj();
}

ReminderRequest::ReminderRequest(ReminderType reminderType)
{
    reminderType_ = reminderType;
    InitServerObj();
}

bool ReminderRequest::CanRemove() const
{
    if ((state_ & (REMINDER_STATUS_SHOWING | REMINDER_STATUS_ALERTING | REMINDER_STATUS_ACTIVE)) == 0) {
        return true;
    }
    return false;
}

bool ReminderRequest::CanShow() const
{
    // when system time change by user manually, and the reminde is to show immediately,
    // the show reminder just need to be triggered by ReminderDataManager#RefreshRemindersLocked(uint8_t).
    // we need to make the REMINDER_EVENT_ALARM_ALERT do nothing.
    uint64_t nowInstantMilli = GetNowInstantMilli();
    if (nowInstantMilli == 0) {
        return false;
    }
    if ((nowInstantMilli - GetReminderTimeInMilli()) < MIN_TIME_INTERVAL_IN_MILLI) {
        return false;
    }
    return true;
}

std::string ReminderRequest::Dump() const
{
    const time_t nextTriggerTime = static_cast<time_t>(triggerTimeInMilli_ / MILLI_SECONDS);
    std::string dateTimeInfo = GetTimeInfoInner(nextTriggerTime, TimeFormat::YMDHMS, true);
    return "Reminder["
           "reminderId=" + std::to_string(reminderId_) +
           ", type=" + std::to_string(static_cast<uint8_t>(reminderType_)) +
           ", state=" + GetState(state_) +
           ", nextTriggerTime=" + dateTimeInfo.c_str() +
           "]";
}

ReminderRequest& ReminderRequest::SetActionButton(const std::string &title, const ActionButtonType &type,
    const std::shared_ptr<ButtonWantAgent> &buttonWantAgent,
    const std::shared_ptr<ButtonDataShareUpdate> &buttonDataShareUpdate)
{
    if ((type != ActionButtonType::CLOSE) && (type != ActionButtonType::SNOOZE) && (type != ActionButtonType::CUSTOM)) {
        ANSR_LOGI("Button type is not support: %{public}d.", static_cast<uint8_t>(type));
        return *this;
    }
    ActionButtonInfo actionButtonInfo;
    actionButtonInfo.type = type;
    actionButtonInfo.title = title;
    actionButtonInfo.wantAgent = buttonWantAgent;
    actionButtonInfo.dataShareUpdate = buttonDataShareUpdate;

    actionButtonMap_.insert(std::pair<ActionButtonType, ActionButtonInfo>(type, actionButtonInfo));
    return *this;
}

ReminderRequest& ReminderRequest::SetContent(const std::string &content)
{
    content_ = content;
    return *this;
}

ReminderRequest& ReminderRequest::SetExpiredContent(const std::string &expiredContent)
{
    expiredContent_ = expiredContent;
    return *this;
}

void ReminderRequest::SetExpired(bool isExpired)
{
    isExpired_ = isExpired;
}

void ReminderRequest::InitReminderId()
{
    std::lock_guard<std::mutex> lock(std::mutex);
    if (GLOBAL_ID < 0) {
        ANSR_LOGW("GLOBAL_ID overdule");
        GLOBAL_ID = 0;
    }
    reminderId_ = ++GLOBAL_ID;
    ANSR_LOGI("reminderId_=%{public}d", reminderId_);
}

void ReminderRequest::InitUserId(const int32_t &userId)
{
    userId_ = userId;
}

void ReminderRequest::InitUid(const int32_t &uid)
{
    uid_ = uid;
}

bool ReminderRequest::IsExpired() const
{
    return isExpired_;
}

bool ReminderRequest::IsShowing() const
{
    if ((state_ & REMINDER_STATUS_SHOWING) != 0) {
        return true;
    }
    return false;
}

void ReminderRequest::OnClose(bool updateNext)
{
    if ((state_ & REMINDER_STATUS_SHOWING) == 0) {
        ANSR_LOGE("onClose, the state of reminder is incorrect, state:%{public}s", GetState(state_).c_str());
        return;
    }
    SetState(false, REMINDER_STATUS_SHOWING | REMINDER_STATUS_SNOOZE, "onClose()");
    if ((state_ & REMINDER_STATUS_ALERTING) != 0) {
        SetState(false, REMINDER_STATUS_ALERTING, "onClose");
    }
    if (updateNext) {
        uint64_t nextTriggerTime = PreGetNextTriggerTimeIgnoreSnooze(true, false);
        if (nextTriggerTime == INVALID_LONG_LONG_VALUE) {
            isExpired_ = true;
        } else {
            SetTriggerTimeInMilli(nextTriggerTime);
            snoozeTimesDynamic_ = snoozeTimes_;
        }
    }
}

bool ReminderRequest::OnDateTimeChange()
{
    uint64_t nextTriggerTime = PreGetNextTriggerTimeIgnoreSnooze(true, false);
    return HandleSysTimeChange(triggerTimeInMilli_, nextTriggerTime);
}

bool ReminderRequest::HandleSysTimeChange(uint64_t oriTriggerTime, uint64_t optTriggerTime)
{
    if (isExpired_) {
        return false;
    }
    uint64_t now = GetNowInstantMilli();
    if (now == 0) {
        ANSR_LOGE("get now time failed.");
        return false;
    }
    if (oriTriggerTime == 0 && optTriggerTime < now) {
        ANSR_LOGW("trigger time is less than now time.");
        return false;
    }
    bool showImmediately = false;
    if (optTriggerTime != INVALID_LONG_LONG_VALUE && (optTriggerTime <= oriTriggerTime || oriTriggerTime == 0)) {
        // case1. switch to a previous time
        SetTriggerTimeInMilli(optTriggerTime);
        snoozeTimesDynamic_ = snoozeTimes_;
    } else {
        if (oriTriggerTime <= now) {
            // case2. switch to a future time, trigger time is less than now time.
            // when the reminder show immediately, trigger time will update in onShow function.
            snoozeTimesDynamic_ = 0;
            showImmediately = true;
        } else {
            // case3. switch to a future time, trigger time is larger than now time.
            showImmediately = false;
        }
    }
    return showImmediately;
}

bool ReminderRequest::HandleTimeZoneChange(
    uint64_t oldZoneTriggerTime, uint64_t newZoneTriggerTime, uint64_t optTriggerTime)
{
    if (isExpired_) {
        return false;
    }
    ANSR_LOGD("Handle timezone change, oldZoneTriggerTime:%{public}" PRIu64 "\
        , newZoneTriggerTime:%{public}" PRIu64 "", oldZoneTriggerTime, newZoneTriggerTime);
    if (oldZoneTriggerTime == newZoneTriggerTime) {
        return false;
    }
    bool showImmediately = false;
    if (optTriggerTime != INVALID_LONG_LONG_VALUE && oldZoneTriggerTime < newZoneTriggerTime) {
        // case1. timezone change to smaller
        SetTriggerTimeInMilli(optTriggerTime);
        snoozeTimesDynamic_ = snoozeTimes_;
    } else {
        // case2. timezone change to larger
        time_t now;
        (void)time(&now);  // unit is seconds.
        if (static_cast<int64_t>(now) < 0) {
            ANSR_LOGE("Get now time error");
            return false;
        }
        if (newZoneTriggerTime <= GetDurationSinceEpochInMilli(now)) {
            snoozeTimesDynamic_ = 0;
            showImmediately = true;
        } else {
            SetTriggerTimeInMilli(newZoneTriggerTime);
            showImmediately = false;
        }
    }
    return showImmediately;
}

void ReminderRequest::OnSameNotificationIdCovered()
{
    SetState(false, REMINDER_STATUS_ALERTING | REMINDER_STATUS_SHOWING | REMINDER_STATUS_SNOOZE,
        "OnSameNotificationIdCovered");
}

void ReminderRequest::OnShow(bool isPlaySoundOrVibration, bool isSysTimeChanged, bool allowToNotify)
{
    if ((state_ & (REMINDER_STATUS_ACTIVE | REMINDER_STATUS_SNOOZE)) != 0) {
        SetState(false, REMINDER_STATUS_ACTIVE | REMINDER_STATUS_SNOOZE, "onShow()");
    }
    if (isSysTimeChanged) {
        uint64_t nowInstantMilli = GetNowInstantMilli();
        if (nowInstantMilli == 0) {
            ANSR_LOGW("Onshow, get now time error");
        }
        reminderTimeInMilli_ = nowInstantMilli;
    } else {
        reminderTimeInMilli_ = triggerTimeInMilli_;
    }
    UpdateNextReminder(false);
    if (allowToNotify) {
        SetState(true, REMINDER_STATUS_SHOWING, "OnShow");
        if (isPlaySoundOrVibration) {
            SetState(true, REMINDER_STATUS_ALERTING, "OnShow");
        }
        UpdateNotificationStateForAlert();
    }
}

void ReminderRequest::OnShowFail()
{
    SetState(false, REMINDER_STATUS_SHOWING, "OnShowFailed()");
}

bool ReminderRequest::OnSnooze()
{
    if ((state_ & REMINDER_STATUS_SNOOZE) != 0) {
        ANSR_LOGW("onSnooze, the state of reminder is incorrect, state: %{public}s", (GetState(state_)).c_str());
        return false;
    }
    if ((state_ & REMINDER_STATUS_ALERTING) != 0) {
        SetState(false, REMINDER_STATUS_ALERTING, "onSnooze()");
    }
    SetSnoozeTimesDynamic(GetSnoozeTimes());
    if (!UpdateNextReminder(true)) {
        return false;
    }
    UpdateNotificationStateForSnooze();
    if (timeIntervalInMilli_ > 0) {
        SetState(true, REMINDER_STATUS_SNOOZE, "onSnooze()");
    }
    return true;
}

void ReminderRequest::OnStart()
{
    if ((state_ & REMINDER_STATUS_ACTIVE) != 0) {
        ANSR_LOGE(
            "start failed, the state of reminder is incorrect, state: %{public}s", (GetState(state_)).c_str());
        return;
    }
    if (isExpired_) {
        ANSR_LOGE("start failed, the reminder is expired");
        return;
    }
    SetState(true, REMINDER_STATUS_ACTIVE, "OnStart()");
}

void ReminderRequest::OnStop()
{
    ANSR_LOGI("Stop the previous active reminder, %{public}s", this->Dump().c_str());
    if ((state_ & REMINDER_STATUS_ACTIVE) == 0) {
        ANSR_LOGW("onStop, the state of reminder is incorrect, state: %{public}s", (GetState(state_)).c_str());
        return;
    }
    SetState(false, REMINDER_STATUS_ACTIVE, "OnStop");
}

bool ReminderRequest::OnTerminate()
{
    if ((state_ & REMINDER_STATUS_ALERTING) == 0) {
        ANSR_LOGW("onTerminate, the state of reminder is %{public}s", (GetState(state_)).c_str());
        return false;
    }
    SetState(false, REMINDER_STATUS_ALERTING, "onTerminate");
    UpdateNotificationStateForAlert();
    return true;
}

bool ReminderRequest::OnTimeZoneChange()
{
    time_t oldZoneTriggerTime = static_cast<time_t>(triggerTimeInMilli_ / MILLI_SECONDS);
    struct tm oriTime;
    (void)gmtime_r(&oldZoneTriggerTime, &oriTime);
    time_t newZoneTriggerTime = mktime(&oriTime);
    uint64_t nextTriggerTime = PreGetNextTriggerTimeIgnoreSnooze(true, false);
    return HandleTimeZoneChange(
        triggerTimeInMilli_, GetDurationSinceEpochInMilli(newZoneTriggerTime), nextTriggerTime);
}

int64_t ReminderRequest::RecoverInt64FromDb(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    const std::string &columnName, const DbRecoveryType &columnType)
{
    if (resultSet == nullptr) {
        ANSR_LOGE("ResultSet is null");
        return 0;
    }
    switch (columnType) {
        case (DbRecoveryType::INT): {
            int32_t value;
            resultSet->GetInt(ReminderStore::GetColumnIndex(columnName), value);
            return static_cast<int64_t>(value);
        }
        case (DbRecoveryType::LONG): {
            int64_t value;
            resultSet->GetLong(ReminderStore::GetColumnIndex(columnName), value);
            return value;
        }
        default: {
            ANSR_LOGD("ColumnType not support.");
            break;
        }
    }
    ANSR_LOGE("Recover data error");
    return 0;
}

void ReminderRequest::RecoverFromDb(const std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        ANSR_LOGE("ResultSet is null");
        return;
    }

    // reminderId
    resultSet->GetInt(ReminderStore::GetColumnIndex(REMINDER_ID), reminderId_);

    // userId
    resultSet->GetInt(ReminderStore::GetColumnIndex(USER_ID), userId_);

    // bundleName
    resultSet->GetString(ReminderStore::GetColumnIndex(PKG_NAME), bundleName_);

    // uid
    resultSet->GetInt(ReminderStore::GetColumnIndex(UID), uid_);

    // isSystemApp
    std::string isSysApp;
    resultSet->GetString(ReminderStore::GetColumnIndex(SYS_APP), isSysApp);
    isSystemApp_ = isSysApp == "true" ? true : false;

    // reminderType
    int32_t reminderType;
    resultSet->GetInt(ReminderStore::GetColumnIndex(REMINDER_TYPE), reminderType);
    reminderType_ = ReminderType(reminderType);

    // reminderTime
    reminderTimeInMilli_ =
        static_cast<uint64_t>(RecoverInt64FromDb(resultSet, REMINDER_TIME, DbRecoveryType::LONG));

    // triggerTime
    triggerTimeInMilli_ =
        static_cast<uint64_t>(RecoverInt64FromDb(resultSet, TRIGGER_TIME, DbRecoveryType::LONG));

    // timeInterval
    uint64_t timeIntervalInSecond =
        static_cast<uint64_t>(RecoverInt64FromDb(resultSet, TIME_INTERVAL, DbRecoveryType::LONG));
    SetTimeInterval(timeIntervalInSecond);

    // snoozeTimes
    snoozeTimes_ = static_cast<uint8_t>(RecoverInt64FromDb(resultSet, SNOOZE_TIMES, DbRecoveryType::INT));

    // dynamicSnoozeTimes
    snoozeTimesDynamic_ =
        static_cast<uint8_t>(RecoverInt64FromDb(resultSet, DYNAMIC_SNOOZE_TIMES, DbRecoveryType::INT));

    // ringDuration
    uint64_t ringDurationInSecond =
        static_cast<uint64_t>(RecoverInt64FromDb(resultSet, RING_DURATION, DbRecoveryType::LONG));
    SetRingDuration(ringDurationInSecond);

    // isExpired
    std::string isExpired;
    resultSet->GetString(ReminderStore::GetColumnIndex(IS_EXPIRED), isExpired);
    isExpired_ = isExpired == "true" ? true : false;

    // state
    state_ = static_cast<uint8_t>(RecoverInt64FromDb(resultSet, STATE, DbRecoveryType::INT));

    // action buttons
    RecoverActionButton(resultSet);

    // slotType
    int32_t slotType;
    resultSet->GetInt(ReminderStore::GetColumnIndex(SLOT_ID), slotType);
    slotType_ = NotificationConstant::SlotType(slotType);

    // notification id
    resultSet->GetInt(ReminderStore::GetColumnIndex(NOTIFICATION_ID), notificationId_);

    // title
    resultSet->GetString(ReminderStore::GetColumnIndex(TITLE), title_);

    // content
    resultSet->GetString(ReminderStore::GetColumnIndex(CONTENT), content_);

    // snoozeContent
    resultSet->GetString(ReminderStore::GetColumnIndex(SNOOZE_CONTENT), snoozeContent_);

    // expiredContent
    resultSet->GetString(ReminderStore::GetColumnIndex(EXPIRED_CONTENT), expiredContent_);

    InitNotificationRequest();  // must set before wantAgent & maxScreenWantAgent

    // wantAgent
    std::string wantAgent;
    resultSet->GetString(ReminderStore::GetColumnIndex(AGENT), wantAgent);
    RecoverWantAgent(wantAgent, 0);

    // maxScreenWantAgent
    std::string maxScreenWantAgent;
    resultSet->GetString(ReminderStore::GetColumnIndex(MAX_SCREEN_AGENT), maxScreenWantAgent);
    RecoverWantAgent(maxScreenWantAgent, 1);

    // tapDismissed
    std::string tapDismissed;
    resultSet->GetString(ReminderStore::GetColumnIndex(TAP_DISMISSED), tapDismissed);
    tapDismissed_ = tapDismissed == "true" ? true : false;

    // autoDeletedTime
    autoDeletedTime_ =
        static_cast<int64_t>(RecoverInt64FromDb(resultSet, AUTO_DELETED_TIME, DbRecoveryType::LONG));

    // customButtonUri
    resultSet->GetString(ReminderStore::GetColumnIndex(CUSTOM_BUTTON_URI), customButtonUri_);
}

void ReminderRequest::RecoverActionButton(const std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        ANSR_LOGE("ResultSet is null");
        return;
    }
    std::string actionButtonInfo;
    resultSet->GetString(ReminderStore::GetColumnIndex(ACTION_BUTTON_INFO), actionButtonInfo);
    std::vector<std::string> multiButton = StringSplit(actionButtonInfo, SEP_BUTTON_MULTI);
    for (auto button : multiButton) {
        std::vector<std::string> singleButton = StringSplit(button, SEP_BUTTON_SINGLE);
        if (singleButton.size() <= SINGLE_BUTTON_INVALID) {
            ANSR_LOGW("RecoverButton fail");
            return;
        }
        if (singleButton.size() == SINGLE_BUTTON_ONLY_ONE) {
            std::string jsonString = singleButton.at(SINGLE_BUTTON_JSONSTRING);
            nlohmann::json root = nlohmann::json::parse(jsonString);
            std::string type = root.at("type").get<std::string>();
            std::string title = root.at("title").get<std::string>();
            auto buttonWantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
            if (!root["wantAgent"].empty()) {
                nlohmann::json wantAgent = root["wantAgent"];
                buttonWantAgent->pkgName = wantAgent.at("pkgName").get<std::string>();
                buttonWantAgent->abilityName = wantAgent.at("abilityName").get<std::string>();
            }
            auto buttonDataShareUpdate = std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
            if (!root["dataShareUpdate"].empty()) {
                nlohmann::json dataShareUpdate = root["dataShareUpdate"];
                buttonDataShareUpdate->uri = dataShareUpdate.at("uri").get<std::string>();
                buttonDataShareUpdate->equalTo = dataShareUpdate.at("equalTo").get<std::string>();
                buttonDataShareUpdate->valuesBucket = dataShareUpdate.at("valuesBucket").get<std::string>();
            }
            SetActionButton(title, ActionButtonType(std::stoi(type, nullptr)),
                buttonWantAgent, buttonDataShareUpdate);
            continue;
        }
        // old method Soon to be deleted
        if (singleButton.size() < SINGLE_BUTTON_MIN_LEN) {
            ANSR_LOGW("RecoverButton fail");
            return;
        }
        auto buttonWantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
        if (singleButton.size() == SINGLE_BUTTON_MAX_LEN) {
            buttonWantAgent->pkgName = singleButton.at(BUTTON_PKG_INDEX);
            buttonWantAgent->abilityName = singleButton.at(BUTTON_ABILITY_INDEX);
        }
        auto buttonDataShareUpdate = std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
        SetActionButton(singleButton.at(BUTTON_TITLE_INDEX),
            ActionButtonType(std::stoi(singleButton.at(BUTTON_TYPE_INDEX), nullptr)),
            buttonWantAgent, buttonDataShareUpdate);
        ANSR_LOGI("RecoverButton title:%{public}s, pkgName:%{public}s, abilityName:%{public}s",
            singleButton.at(BUTTON_TITLE_INDEX).c_str(), buttonWantAgent->pkgName.c_str(),
            buttonWantAgent->abilityName.c_str());
    }
}

std::vector<std::string> ReminderRequest::StringSplit(std::string source, const std::string &split)
{
    std::vector<std::string> result;
    if (source.empty()) {
        return result;
    }
    size_t pos = 0;
    while ((pos = source.find(split)) != std::string::npos) {
        std::string token = source.substr(0, pos);
        if (!token.empty()) {
            result.push_back(token);
        }
        source.erase(0, pos + split.length());
    }
    if (!source.empty()) {
        result.push_back(source);
    }
    return result;
}

void ReminderRequest::RecoverWantAgent(const std::string &wantAgentInfo, const uint8_t &type)
{
    std::vector<std::string> info = StringSplit(wantAgentInfo, ReminderRequest::SEP_WANT_AGENT);
    uint8_t minLen = 2;
    if (info.size() < minLen) {
        ANSR_LOGW("RecoverWantAgent fail");
        return;
    }
    ANSR_LOGD("pkg=%{public}s, ability=%{public}s", info.at(0).c_str(), info.at(1).c_str());
    switch (type) {
        case 0: {
            auto wai = std::make_shared<ReminderRequest::WantAgentInfo>();
            wai->pkgName = info.at(0);
            wai->abilityName = info.at(1);
            if (info.size() > minLen) {
                wai->uri = info.at(2);
            }
            SetWantAgentInfo(wai);
            break;
        }
        case 1: {
            auto maxScreenWantAgentInfo = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
            maxScreenWantAgentInfo->pkgName = info.at(0);
            maxScreenWantAgentInfo->abilityName = info.at(1);
            SetMaxScreenWantAgentInfo(maxScreenWantAgentInfo);
            break;
        }
        default: {
            ANSR_LOGW("RecoverWantAgent type not support");
            break;
        }
    }
}

ReminderRequest& ReminderRequest::SetMaxScreenWantAgentInfo(
    const std::shared_ptr<MaxScreenAgentInfo> &maxScreenWantAgentInfo)
{
    maxScreenWantAgentInfo_ = maxScreenWantAgentInfo;
    return *this;
}

ReminderRequest& ReminderRequest::SetNotificationId(int32_t notificationId)
{
    notificationId_ = notificationId;
    return *this;
}

ReminderRequest& ReminderRequest::SetSlotType(const NotificationConstant::SlotType &slotType)
{
    slotType_ = slotType;
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeContent(const std::string &snoozeContent)
{
    snoozeContent_ = snoozeContent;
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeTimes(const uint8_t snoozeTimes)
{
    snoozeTimes_ = snoozeTimes;
    SetSnoozeTimesDynamic(snoozeTimes);
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeTimesDynamic(const uint8_t snooziTimes)
{
    snoozeTimesDynamic_ = snooziTimes;
    return *this;
}

ReminderRequest& ReminderRequest::SetTimeInterval(const uint64_t timeIntervalInSeconds)
{
    if (timeIntervalInSeconds > (UINT64_MAX / MILLI_SECONDS)) {
        ANSR_LOGW("SetTimeInterval, replace to set (0s), for the given is out of legal range");
        timeIntervalInMilli_ = 0;
    } else {
        uint64_t timeIntervalInMilli = timeIntervalInSeconds * MILLI_SECONDS;
        if (timeIntervalInMilli > 0 && timeIntervalInMilli < MIN_TIME_INTERVAL_IN_MILLI) {
            ANSR_LOGW("SetTimeInterval, replace to set %{public}u, for the given is 0<%{public}" PRIu64 "<%{public}u",
                MIN_TIME_INTERVAL_IN_MILLI / MILLI_SECONDS, timeIntervalInSeconds,
                MIN_TIME_INTERVAL_IN_MILLI / MILLI_SECONDS);
            timeIntervalInMilli_ = MIN_TIME_INTERVAL_IN_MILLI;
        } else {
            timeIntervalInMilli_ = timeIntervalInMilli;
        }
    }
    return *this;
}

ReminderRequest& ReminderRequest::SetTitle(const std::string &title)
{
    title_ = title;
    return *this;
}

void ReminderRequest::SetTriggerTimeInMilli(uint64_t triggerTimeInMilli)
{
    triggerTimeInMilli_ = triggerTimeInMilli;
}

ReminderRequest& ReminderRequest::SetWantAgentInfo(const std::shared_ptr<WantAgentInfo> &wantAgentInfo)
{
    wantAgentInfo_ = wantAgentInfo;
    return *this;
}

bool ReminderRequest::ShouldShowImmediately() const
{
    uint64_t nowInstantMilli = GetNowInstantMilli();
    if (nowInstantMilli == 0) {
        return false;
    }
    if (triggerTimeInMilli_ > nowInstantMilli) {
        return false;
    }
    return true;
}

std::map<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo> ReminderRequest::GetActionButtons(
    ) const
{
    return actionButtonMap_;
}

std::string ReminderRequest::GetContent() const
{
    return content_;
}

std::string ReminderRequest::GetExpiredContent() const
{
    return expiredContent_;
}

std::shared_ptr<ReminderRequest::MaxScreenAgentInfo> ReminderRequest::GetMaxScreenWantAgentInfo() const
{
    return maxScreenWantAgentInfo_;
}

int32_t ReminderRequest::GetNotificationId() const
{
    return notificationId_;
}

sptr<NotificationRequest> ReminderRequest::GetNotificationRequest() const
{
    return notificationRequest_;
}

int32_t ReminderRequest::GetReminderId() const
{
    return reminderId_;
}

uint64_t ReminderRequest::GetReminderTimeInMilli() const
{
    return reminderTimeInMilli_;
}

void ReminderRequest::SetReminderId(int32_t reminderId)
{
    reminderId_ = reminderId;
}

void ReminderRequest::SetReminderTimeInMilli(const uint64_t reminderTimeInMilli)
{
    reminderTimeInMilli_ = reminderTimeInMilli;
}

ReminderRequest& ReminderRequest::SetRingDuration(const uint64_t ringDurationInSeconds)
{
    if ((ringDurationInSeconds == 0) || (ringDurationInSeconds > (UINT64_MAX / MILLI_SECONDS))) {
        ANSR_LOGW("setRingDuration, replace to set (1s), for the given is out of legal range");
        ringDurationInMilli_ = MILLI_SECONDS;
    } else {
        ringDurationInMilli_ = ringDurationInSeconds * MILLI_SECONDS;
    }
    return *this;
}

NotificationConstant::SlotType ReminderRequest::GetSlotType() const
{
    return slotType_;
}

std::string ReminderRequest::GetSnoozeContent() const
{
    return snoozeContent_;
}

uint8_t ReminderRequest::GetSnoozeTimes() const
{
    return snoozeTimes_;
}

uint8_t ReminderRequest::GetSnoozeTimesDynamic() const
{
    return snoozeTimesDynamic_;
}

uint8_t ReminderRequest::GetState() const
{
    return state_;
}

uint64_t ReminderRequest::GetTimeInterval() const
{
    return timeIntervalInMilli_ / MILLI_SECONDS;
}

std::string ReminderRequest::GetTitle() const
{
    return title_;
}

uint64_t ReminderRequest::GetTriggerTimeInMilli() const
{
    return triggerTimeInMilli_;
}

int32_t ReminderRequest::GetUserId() const
{
    return userId_;
}

int32_t ReminderRequest::GetUid() const
{
    return uid_;
}

void ReminderRequest::SetSystemApp(bool isSystem)
{
    isSystemApp_ = isSystem;
}

bool ReminderRequest::IsSystemApp() const
{
    return isSystemApp_;
}

void ReminderRequest::SetTapDismissed(bool tapDismissed)
{
    tapDismissed_ = tapDismissed;
}

bool ReminderRequest::IsTapDismissed() const
{
    return tapDismissed_;
}

void ReminderRequest::SetAutoDeletedTime(int64_t autoDeletedTime)
{
    autoDeletedTime_ = autoDeletedTime;
}

int64_t ReminderRequest::GetAutoDeletedTime() const
{
    return autoDeletedTime_;
}

void ReminderRequest::SetCustomButtonUri(const std::string &uri)
{
    customButtonUri_ = uri;
}

std::string ReminderRequest::GetCustomButtonUri() const
{
    return customButtonUri_;
}

std::shared_ptr<ReminderRequest::WantAgentInfo> ReminderRequest::GetWantAgentInfo() const
{
    return wantAgentInfo_;
}

ReminderRequest::ReminderType ReminderRequest::GetReminderType() const
{
    return reminderType_;
}

uint16_t ReminderRequest::GetRingDuration() const
{
    return ringDurationInMilli_ / MILLI_SECONDS;
}

bool ReminderRequest::UpdateNextReminder()
{
    return false;
}

bool ReminderRequest::SetNextTriggerTime()
{
    return false;
}

void ReminderRequest::UpdateNotificationRequest(UpdateNotificationType type, std::string extra)
{
    switch (type) {
        case UpdateNotificationType::COMMON: {
            ANSR_LOGI("UpdateNotification common information");
            UpdateNotificationCommon();
            break;
        }
        case UpdateNotificationType::REMOVAL_WANT_AGENT: {
            ANSR_LOGI("UpdateNotification removal_want_agent");
            AddRemovalWantAgent();
            break;
        }
        case UpdateNotificationType::WANT_AGENT: {
            ANSR_LOGI("UpdateNotification want_agent");
            AppExecFwk::ElementName wantAgent("", wantAgentInfo_->pkgName, wantAgentInfo_->abilityName);
            SetWantAgent(wantAgent);
            break;
        }
        case UpdateNotificationType::MAX_SCREEN_WANT_AGENT: {
            ANSR_LOGI("UpdateNotification max_screen_want_agent");
            AppExecFwk::ElementName maxScreenWantAgent(
                "", maxScreenWantAgentInfo_->pkgName, maxScreenWantAgentInfo_->abilityName);
            SetMaxScreenWantAgent(maxScreenWantAgent);
            break;
        }
        case UpdateNotificationType::BUNDLE_INFO: {
            ANSR_LOGI("UpdateNotification hap information");
            UpdateNotificationBundleInfo();
            break;
        }
        case UpdateNotificationType::CONTENT: {
            break;
        }
        default:
            break;
    }
}

bool ReminderRequest::Marshalling(Parcel &parcel) const
{
    // write string
    if (!parcel.WriteString(content_)) {
        ANSR_LOGE("Failed to write content");
        return false;
    }
    if (!parcel.WriteString(expiredContent_)) {
        ANSR_LOGE("Failed to write expiredContent");
        return false;
    }
    if (!parcel.WriteString(snoozeContent_)) {
        ANSR_LOGE("Failed to write snoozeContent");
        return false;
    }
    if (!parcel.WriteString(title_)) {
        ANSR_LOGE("Failed to write title");
        return false;
    }
    if (!parcel.WriteString(wantAgentInfo_->abilityName)) {
        ANSR_LOGE("Failed to write wantAgentInfo`s abilityName");
        return false;
    }
    if (!parcel.WriteString(wantAgentInfo_->pkgName)) {
        ANSR_LOGE("Failed to write wantAgentInfo`s pkgName");
        return false;
    }
    if (!parcel.WriteString(wantAgentInfo_->uri)) {
        ANSR_LOGE("Failed to write wantAgentInfo`s uri");
        return false;
    }
    if (!parcel.WriteString(maxScreenWantAgentInfo_->abilityName)) {
        ANSR_LOGE("Failed to write maxScreenWantAgentInfo`s abilityName");
        return false;
    }
    if (!parcel.WriteString(maxScreenWantAgentInfo_->pkgName)) {
        ANSR_LOGE("Failed to write maxScreenWantAgentInfo`s pkgName");
        return false;
    }
    if (!parcel.WriteString(customButtonUri_)) {
        ANSR_LOGE("Failed to write customButtonUri");
        return false;
    }

    // write bool
    if (!parcel.WriteBool(isExpired_)) {
        ANSR_LOGE("Failed to write isExpired");
        return false;
    }
    if (!parcel.WriteBool(isSystemApp_)) {
        ANSR_LOGE("Failed to write isSystemApp");
        return false;
    }
    if (!parcel.WriteBool(tapDismissed_)) {
        ANSR_LOGE("Failed to write tapDismissed");
        return false;
    }

    // write int
    if (!parcel.WriteInt64(autoDeletedTime_)) {
        ANSR_LOGE("Failed to write autoDeletedTime");
        return false;
    }
    if (!parcel.WriteInt32(reminderId_)) {
        ANSR_LOGE("Failed to write reminderId");
        return false;
    }
    if (!parcel.WriteInt32(notificationId_)) {
        ANSR_LOGE("Failed to write notificationId");
        return false;
    }
    if (!parcel.WriteUint64(triggerTimeInMilli_)) {
        ANSR_LOGE("Failed to write triggerTimeInMilli");
        return false;
    }
    if (!parcel.WriteUint64(timeIntervalInMilli_)) {
        ANSR_LOGE("Failed to write timeIntervalInMilli");
        return false;
    }
    if (!parcel.WriteUint64(ringDurationInMilli_)) {
        ANSR_LOGE("Failed to write ringDurationInMilli");
        return false;
    }
    if (!parcel.WriteUint64(reminderTimeInMilli_)) {
        ANSR_LOGE("Failed to write reminderTimeInMilli");
        return false;
    }
    if (!parcel.WriteUint8(snoozeTimes_)) {
        ANSR_LOGE("Failed to write snoozeTimes");
        return false;
    }
    if (!parcel.WriteUint8(snoozeTimesDynamic_)) {
        ANSR_LOGE("Failed to write snoozeTimesDynamic");
        return false;
    }
    if (!parcel.WriteUint8(state_)) {
        ANSR_LOGE("Failed to write state");
        return false;
    }

    // write enum
    if (!parcel.WriteUint8(static_cast<uint8_t>(reminderType_))) {
        ANSR_LOGE("Failed to write reminder type");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(slotType_))) {
        ANSR_LOGE("Failed to write slot type");
        return false;
    }

    // write map
    if (!parcel.WriteUint64(static_cast<uint64_t>(actionButtonMap_.size()))) {
        ANSR_LOGE("Failed to write action button size");
        return false;
    }
    for (auto button : actionButtonMap_) {
        if (!parcel.WriteUint8(static_cast<uint8_t>(button.first))) {
            ANSR_LOGE("Failed to write action button type");
            return false;
        }
        if (!parcel.WriteString(static_cast<std::string>(button.second.title))) {
            ANSR_LOGE("Failed to write action button title");
            return false;
        }
        if (button.second.wantAgent == nullptr) {
            ANSR_LOGE("button wantAgent is null");
            return false;
        }
        if (!parcel.WriteString(button.second.wantAgent->pkgName)) {
            ANSR_LOGE("Failed to write action button pkgName");
            return false;
        }
        if (!parcel.WriteString(button.second.wantAgent->abilityName)) {
            ANSR_LOGE("Failed to write action button abilityName");
            return false;
        }
        if (button.second.dataShareUpdate == nullptr) {
            ANSR_LOGE("button dataShareUpdate is null");
            return false;
        }
        if (!parcel.WriteString(button.second.dataShareUpdate->uri)) {
            ANSR_LOGE("Failed to write action button dataShareUpdate uri");
            return false;
        }
        if (!parcel.WriteString(button.second.dataShareUpdate->equalTo)) {
            ANSR_LOGE("Failed to write action button dataShareUpdate equalTo");
            return false;
        }
        if (!parcel.WriteString(button.second.dataShareUpdate->valuesBucket)) {
            ANSR_LOGE("Failed to write action button dataShareUpdate valuesBucket");
            return false;
        }
    }
    return true;
}

ReminderRequest *ReminderRequest::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) ReminderRequest();
    if (objptr == nullptr) {
        ANSR_LOGE("Failed to create reminder due to no memory.");
        return objptr;
    }
    if (!objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool ReminderRequest::ReadFromParcel(Parcel &parcel)
{
    // read string
    if (!parcel.ReadString(content_)) {
        ANSR_LOGE("Failed to read content");
        return false;
    }
    if (!parcel.ReadString(expiredContent_)) {
        ANSR_LOGE("to read expiredContent");
        return false;
    }
    if (!parcel.ReadString(snoozeContent_)) {
        ANSR_LOGE("to read snoozeContent");
        return false;
    }
    if (!parcel.ReadString(title_)) {
        ANSR_LOGE("Failed to read title");
        return false;
    }
    if (!parcel.ReadString(wantAgentInfo_->abilityName)) {
        ANSR_LOGE("Failed to read wantAgentInfo`s abilityName");
        return false;
    }
    if (!parcel.ReadString(wantAgentInfo_->pkgName)) {
        ANSR_LOGE("Failed to read wantAgentInfo`s pkgName");
        return false;
    }
    if (!parcel.ReadString(wantAgentInfo_->uri)) {
        ANSR_LOGE("Failed to read wantAgentInfo`s uri");
        return false;
    }
    if (!parcel.ReadString(maxScreenWantAgentInfo_->abilityName)) {
        ANSR_LOGE("Failed to read maxScreenWantAgentInfo`s abilityName");
        return false;
    }
    if (!parcel.ReadString(maxScreenWantAgentInfo_->pkgName)) {
        ANSR_LOGE("Failed to read maxScreenWantAgentInfo`s pkgName");
        return false;
    }
    if (!parcel.ReadString(customButtonUri_)) {
        ANSR_LOGE("Failed to read customButtonUri");
        return false;
    }

    // read bool
    if (!parcel.ReadBool(isExpired_)) {
        ANSR_LOGE("Failed to read isExpired");
        return false;
    }
    if (!parcel.ReadBool(isSystemApp_)) {
        ANSR_LOGE("Failed to read isSystemApp");
        return false;
    }
    if (!parcel.ReadBool(tapDismissed_)) {
        ANSR_LOGE("Failed to read tapDismissed");
        return false;
    }

    // read int
    if (!parcel.ReadInt64(autoDeletedTime_)) {
        ANSR_LOGE("Failed to read autoDeletedTime");
        return false;
    }
    int32_t tempReminderId = -1;
    if (!parcel.ReadInt32(tempReminderId)) {
        ANSR_LOGE("Failed to read tempReminderId");
        return false;
    }
    reminderId_ = (tempReminderId == -1) ? reminderId_ : tempReminderId;

    if (!parcel.ReadInt32(notificationId_)) {
        ANSR_LOGE("Failed to read notificationId");
        return false;
    }
    if (!parcel.ReadUint64(triggerTimeInMilli_)) {
        ANSR_LOGE("Failed to read triggerTimeInMilli");
        return false;
    }
    if (!parcel.ReadUint64(timeIntervalInMilli_)) {
        ANSR_LOGE("Failed to read timeIntervalInMilli");
        return false;
    }
    if (!parcel.ReadUint64(ringDurationInMilli_)) {
        ANSR_LOGE("Failed to read ringDurationInMilli");
        return false;
    }
    if (!parcel.ReadUint64(reminderTimeInMilli_)) {
        ANSR_LOGE("Failed to read reminderTimeInMilli");
        return false;
    }
    if (!parcel.ReadUint8(snoozeTimes_)) {
        ANSR_LOGE("Failed to read snoozeTimes");
        return false;
    }
    if (!parcel.ReadUint8(snoozeTimesDynamic_)) {
        ANSR_LOGE("Failed to read snoozeTimesDynamic");
        return false;
    }
    if (!parcel.ReadUint8(state_)) {
        ANSR_LOGE("Failed to read state");
        return false;
    }

    // read enum
    uint8_t reminderType = static_cast<uint8_t>(ReminderType::INVALID);
    if (!parcel.ReadUint8(reminderType)) {
        ANSR_LOGE("Failed to read reminderType");
        return false;
    }
    reminderType_ = static_cast<ReminderType>(reminderType);

    int32_t slotType = static_cast<int32_t>(NotificationConstant::SlotType::OTHER);
    if (!parcel.ReadInt32(slotType)) {
        ANSR_LOGE("Failed to read slotType");
        return false;
    }
    slotType_ = static_cast<NotificationConstant::SlotType>(slotType);

    // read map
    uint64_t buttonMapSize = 0;
    if (!parcel.ReadUint64(buttonMapSize)) {
        ANSR_LOGE("Failed to read buttonMapSize");
        return false;
    }

    buttonMapSize = (buttonMapSize < MAX_ACTION_BUTTON_NUM) ? buttonMapSize : MAX_ACTION_BUTTON_NUM;
    for (uint64_t i = 0; i < buttonMapSize; i++) {
        uint8_t buttonType = static_cast<uint8_t>(ActionButtonType::INVALID);
        if (!parcel.ReadUint8(buttonType)) {
            ANSR_LOGE("Failed to read buttonType");
            return false;
        }
        ActionButtonType type = static_cast<ActionButtonType>(buttonType);
        std::string title = parcel.ReadString();
        std::string pkgName = parcel.ReadString();
        std::string abilityName = parcel.ReadString();
        std::string uri = parcel.ReadString();
        std::string equalTo = parcel.ReadString();
        std::string valuesBucket = parcel.ReadString();
        ActionButtonInfo info;
        info.type = type;
        info.title = title;
        info.wantAgent = std::make_shared<ButtonWantAgent>();
        info.wantAgent->pkgName = pkgName;
        info.wantAgent->abilityName = abilityName;
        info.dataShareUpdate = std::make_shared<ButtonDataShareUpdate>();
        info.dataShareUpdate->uri = uri;
        info.dataShareUpdate->equalTo = equalTo;
        info.dataShareUpdate->valuesBucket = valuesBucket;
        actionButtonMap_.insert(std::pair<ActionButtonType, ActionButtonInfo>(type, info));
    }
    if (!InitNotificationRequest()) {
        return false;
    }
    return true;
}

bool ReminderRequest::InitNotificationRequest()
{
    ANSR_LOGI("Init notification");
    notificationRequest_ = new (std::nothrow) NotificationRequest(notificationId_);
    if (notificationRequest_ == nullptr) {
        ANSR_LOGE("Failed to create notification.");
        return false;
    }
    displayContent_ = content_;
    AddActionButtons(true);
    return true;
}

void ReminderRequest::InitServerObj()
{
    wantAgentInfo_ = wantAgentInfo_ == nullptr ? std::make_shared<WantAgentInfo>() : wantAgentInfo_;
    maxScreenWantAgentInfo_ =
        maxScreenWantAgentInfo_ == nullptr ? std::make_shared<MaxScreenAgentInfo>() : maxScreenWantAgentInfo_;
}

bool ReminderRequest::IsAlerting() const
{
    return (state_ & REMINDER_STATUS_ALERTING) != 0;
}

uint64_t ReminderRequest::GetDurationSinceEpochInMilli(const time_t target)
{
    auto tarEndTimePoint = std::chrono::system_clock::from_time_t(target);
    auto tarDuration = std::chrono::duration_cast<std::chrono::milliseconds>(tarEndTimePoint.time_since_epoch());
    int64_t tarDate = tarDuration.count();
    if (tarDate < 0) {
        ANSR_LOGW("tarDuration is less than 0.");
        return INVALID_LONG_LONG_VALUE;
    }
    return static_cast<uint64_t>(tarDate);
}

std::string ReminderRequest::GetDateTimeInfo(const time_t &timeInSecond) const
{
    return GetTimeInfoInner(timeInSecond, TimeFormat::YMDHMS, true);
}

std::string ReminderRequest::GetButtonInfo() const
{
    std::string info = "";
    bool isFirst = true;
    for (auto button : actionButtonMap_) {
        if (!isFirst) {
            info += SEP_BUTTON_MULTI;
        }
        ActionButtonInfo buttonInfo = button.second;
        nlohmann::json root;
        root["type"] = std::to_string(static_cast<uint8_t>(button.first));
        root["title"] = buttonInfo.title;
        if (buttonInfo.wantAgent != nullptr) {
            nlohmann::json wantAgentfriends;
            wantAgentfriends["pkgName"] = buttonInfo.wantAgent->pkgName;
            wantAgentfriends["abilityName"] = buttonInfo.wantAgent->abilityName;
            root["wantAgent"]  = wantAgentfriends;
        }

        if (buttonInfo.dataShareUpdate != nullptr) {
            nlohmann::json dataShareUpdatefriends;
            dataShareUpdatefriends["uri"] = buttonInfo.dataShareUpdate->uri;
            dataShareUpdatefriends["equalTo"] = buttonInfo.dataShareUpdate->equalTo;
            dataShareUpdatefriends["valuesBucket"] = buttonInfo.dataShareUpdate->valuesBucket;
            root["dataShareUpdate"]  = dataShareUpdatefriends;
        }
        std::string str = root.dump();
        info += str;
        isFirst = false;
    }
    return info;
}

uint64_t ReminderRequest::GetNowInstantMilli() const
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    if (static_cast<int64_t>(now) < 0) {
        ANSR_LOGE("Get now time error");
        return 0;
    }
    return GetDurationSinceEpochInMilli(now);
}

std::string ReminderRequest::GetShowTime(const uint64_t showTime) const
{
    if (reminderType_ == ReminderType::TIMER) {
        return "";
    }
    return GetTimeInfoInner(static_cast<time_t>(showTime / MILLI_SECONDS), TimeFormat::HM, false);
}

std::string ReminderRequest::GetTimeInfoInner(const time_t &timeInSecond, const TimeFormat &format,
    bool keep24Hour) const
{
    const uint8_t dateTimeLen = 80;
    char dateTimeBuffer[dateTimeLen];
    struct tm timeInfo;
    (void)localtime_r(&timeInSecond, &timeInfo);
    bool is24HourClock = OHOS::Global::I18n::LocaleConfig::Is24HourClock();
    if (!is24HourClock && timeInfo.tm_hour > TIME_HOUR_OFFSET && !keep24Hour) {
        timeInfo.tm_hour -= TIME_HOUR_OFFSET;
    }
    switch (format) {
        case TimeFormat::YMDHMS: {
            (void)strftime(dateTimeBuffer, dateTimeLen, "%Y-%m-%d %H:%M:%S", &timeInfo);
            break;
        }
        case TimeFormat::HM: {
            (void)strftime(dateTimeBuffer, dateTimeLen, "%H:%M", &timeInfo);
            break;
        }
        default: {
            ANSR_LOGW("Time format not support.");
            break;
        }
    }
    std::string dateTimeInfo(dateTimeBuffer);
    return dateTimeInfo;
}

std::string ReminderRequest::GetState(const uint8_t state) const
{
    std::string stateInfo = "'";
    if (state == REMINDER_STATUS_INACTIVE) {
        stateInfo += "Inactive";
    } else {
        bool hasSeparator = false;
        if ((state & REMINDER_STATUS_ACTIVE) != 0) {
            stateInfo += "Active";
            hasSeparator = true;
        }
        if ((state & REMINDER_STATUS_ALERTING) != 0) {
            if (hasSeparator) {
                stateInfo += ",";
            }
            stateInfo += "Alerting";
            hasSeparator = true;
        }
        if ((state & REMINDER_STATUS_SHOWING) != 0) {
            if (hasSeparator) {
                stateInfo += ",";
            }
            stateInfo += "Showing";
            hasSeparator = true;
        }
        if ((state & REMINDER_STATUS_SNOOZE) != 0) {
            if (hasSeparator) {
                stateInfo += ",";
            }
            stateInfo += "Snooze";
        }
    }
    stateInfo += "'";
    return stateInfo;
}

void ReminderRequest::AddActionButtons(const bool includeSnooze)
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    for (auto button : actionButtonMap_) {
        auto want = std::make_shared<OHOS::AAFwk::Want>();
        auto type = button.first;
        switch (type) {
            case ActionButtonType::CLOSE:
                want->SetAction(REMINDER_EVENT_CLOSE_ALERT);
                break;
            case ActionButtonType::SNOOZE:
                if (includeSnooze) {
                    want->SetAction(REMINDER_EVENT_SNOOZE_ALERT);
                } else {
                    ANSR_LOGD("Not add action button, type is snooze, as includeSnooze is false");
                    continue;
                }
                break;
            case ActionButtonType::CUSTOM:
                want->SetAction(REMINDER_EVENT_CUSTOM_ALERT);
                if (button.second.wantAgent == nullptr) {
                    return;
                }
                want->SetParam("PkgName", button.second.wantAgent->pkgName);
                want->SetParam("AbilityName", button.second.wantAgent->abilityName);
                break;
            default:
                break;
        }
        want->SetParam(PARAM_REMINDER_ID, reminderId_);
        std::vector<std::shared_ptr<AAFwk::Want>> wants;
        wants.push_back(want);
        auto title = static_cast<std::string>(button.second.title);
        AbilityRuntime::WantAgent::WantAgentInfo buttonWantAgentInfo(
            requestCode,
            AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
            flags,
            wants,
            nullptr
        );

        std::string identity = IPCSkeleton::ResetCallingIdentity();
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> buttonWantAgent =
            AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(buttonWantAgentInfo, userId_);
        IPCSkeleton::SetCallingIdentity(identity);

        std::shared_ptr<NotificationActionButton> actionButton
            = NotificationActionButton::Create(nullptr, title, buttonWantAgent);
        notificationRequest_->AddActionButton(actionButton);
    }
}

void ReminderRequest::AddRemovalWantAgent()
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetAction(REMINDER_EVENT_REMOVE_NOTIFICATION);
    want->SetParam(PARAM_REMINDER_ID, reminderId_);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags,
        wants,
        nullptr
    );

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, userId_);
    IPCSkeleton::SetCallingIdentity(identity);

    notificationRequest_->SetRemovalWantAgent(wantAgent);
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> ReminderRequest::CreateWantAgent(
    AppExecFwk::ElementName &element, bool isWantAgent) const
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetElement(element);
    if (isWantAgent) {
        want->SetUri(wantAgentInfo_->uri);
    }
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY,
        flags,
        wants,
        nullptr
    );
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto wantAgent = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, userId_);
    IPCSkeleton::SetCallingIdentity(identity);
    return wantAgent;
}

void ReminderRequest::SetMaxScreenWantAgent(AppExecFwk::ElementName &element)
{
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = CreateWantAgent(element, false);
    notificationRequest_->SetMaxScreenWantAgent(wantAgent);
}

void ReminderRequest::SetWantAgent(AppExecFwk::ElementName &element)
{
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = CreateWantAgent(element, true);
    notificationRequest_->SetWantAgent(wantAgent);
}

void ReminderRequest::SetState(bool deSet, const uint8_t newState, std::string function)
{
    uint8_t oldState = state_;
    if (deSet) {
        state_ |= newState;
    } else {
        state_ &= static_cast<uint8_t>(~newState);
    }
    ANSR_LOGI("Switch the reminder(reminderId=%{public}d) state, from %{public}s to %{public}s, called by %{public}s",
        reminderId_, GetState(oldState).c_str(), GetState(state_).c_str(), function.c_str());
}

void ReminderRequest::UpdateActionButtons(const bool &setSnooze)
{
    if (notificationRequest_ == nullptr) {
        ANSR_LOGE("updateActionButtons failed, the notificationRequest is null");
        return;
    }
    notificationRequest_->ClearActionButtons();
    if (setSnooze) {
        AddActionButtons(false);
    } else {
        AddActionButtons(true);
    }
}

bool ReminderRequest::UpdateNextReminder(const bool &force)
{
    bool result = true;
    if (force) {
        uint64_t nowInstantMilli = GetNowInstantMilli();
        if (nowInstantMilli == 0) {
            result = false;
        } else {
            triggerTimeInMilli_ = nowInstantMilli + timeIntervalInMilli_;
            snoozeTimesDynamic_ = snoozeTimes_;
            if (timeIntervalInMilli_ != 0) {
                isExpired_ = false;
            }
        }
    } else {
        result = UpdateNextReminder();
    }
    std::string info = result ? "success" : "no next";
    ANSR_LOGI("updateNextReminder(id=%{public}d, %{public}s): force=%{public}d, trigger time is: %{public}s",
        reminderId_, info.c_str(), force,
        GetDateTimeInfo(static_cast<time_t>(triggerTimeInMilli_ / MILLI_SECONDS)).c_str());
    return result;
}

void ReminderRequest::UpdateNotificationCommon()
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    notificationRequest_->SetDeliveryTime(GetDurationSinceEpochInMilli(now));
    notificationRequest_->SetLabel(NOTIFICATION_LABEL);
    notificationRequest_->SetShowDeliveryTime(true);
    notificationRequest_->SetSlotType(slotType_);
    notificationRequest_->SetTapDismissed(tapDismissed_);
    notificationRequest_->SetAutoDeletedTime(autoDeletedTime_);
    auto notificationNormalContent = std::make_shared<NotificationNormalContent>();
    notificationNormalContent->SetText(displayContent_);
    notificationNormalContent->SetTitle(title_);
    auto notificationContent = std::make_shared<NotificationContent>(notificationNormalContent);
    notificationRequest_->SetContent(notificationContent);
    if ((reminderType_ == ReminderRequest::ReminderType::TIMER) ||
        (reminderType_ == ReminderRequest::ReminderType::ALARM)) {
        notificationRequest_->SetUnremovable(true);
    }
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::CLOSE);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::CLOSE);
    notificationRequest_->SetFlags(flags);
}

void ReminderRequest::UpdateNotificationBundleInfo()
{
    std::string ownerBundleName = notificationRequest_->GetOwnerBundleName();
    if (!(ownerBundleName.empty())) {
        return;
    }
    ANSR_LOGD("ownerBundleName=%{public}s, bundleName_=%{public}s",
        ownerBundleName.c_str(), bundleName_.c_str());
    notificationRequest_->SetOwnerBundleName(bundleName_);
    notificationRequest_->SetCreatorBundleName(bundleName_);
    notificationRequest_->SetCreatorUid(uid_);
    ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    if (errCode != ERR_OK) {
        ANSR_LOGE("GetOsAccountLocalIdFromUid fail.");
        return;
    }
    notificationRequest_->SetCreatorUserId(userId_);
}

void ReminderRequest::UpdateNotificationContent(const bool &setSnooze)
{
    if (notificationRequest_ == nullptr) {
        ANSR_LOGE("updateNotificationContent failed, the notificationRequest is null");
        return;
    }
    std::string extendContent = "";
    if (setSnooze) {
        if (timeIntervalInMilli_ != 0) {
            // snooze the reminder by manual
            extendContent = snoozeContent_;
            notificationRequest_->SetTapDismissed(false);
        } else {
            // the reminder is expired now, when timeInterval is 0
            extendContent = expiredContent_;
        }
    } else if (IsAlerting()) {
        // the reminder is alerting, or ring duration is 0
        extendContent = "";
    } else if (snoozeTimesDynamic_ != snoozeTimes_) {
        // the reminder is snoozing by period artithmetic, when the ring duration is over.
        extendContent = snoozeContent_;
        notificationRequest_->SetTapDismissed(false);
    } else {
        // the reminder has already snoozed by period arithmetic, when the ring duration is over.
        extendContent = expiredContent_;
    }
    if (extendContent == "") {
        displayContent_ = content_;
    } else {
        displayContent_ = extendContent;
    }
    ANSR_LOGD("Display content=%{public}s", displayContent_.c_str());
}

void ReminderRequest::UpdateNotificationStateForAlert()
{
    ANSR_LOGD("UpdateNotification content and buttons");
    UpdateNotificationContent(false);
    UpdateActionButtons(false);
}

void ReminderRequest::UpdateNotificationStateForSnooze()
{
    ANSR_LOGD("UpdateNotification content and buttons");
    UpdateNotificationContent(true);
    UpdateActionButtons(true);
}

int32_t ReminderRequest::GetActualTime(const TimeTransferType &type, int32_t cTime)
{
    switch (type) {
        case (TimeTransferType::YEAR):  // year
            return BASE_YEAR + cTime;
        case (TimeTransferType::MONTH):  // month
            return 1 + cTime;
        case (TimeTransferType::WEEK): {  // week
            return cTime == 0 ? SUNDAY : cTime;
        }
        default:
            return -1;
    }
}

int32_t ReminderRequest::GetCTime(const TimeTransferType &type, int32_t actualTime)
{
    switch (type) {
        case (TimeTransferType::YEAR):  // year
            return actualTime - BASE_YEAR;
        case (TimeTransferType::MONTH):  // month
            return actualTime - 1;
        case (TimeTransferType::WEEK): {  // week
            return actualTime == SUNDAY ? 0 : actualTime;
        }
        default:
            return -1;
    }
}

int32_t ReminderRequest::GetUid(const int32_t &userId, const std::string &bundleName)
{
    AppExecFwk::ApplicationInfo info;
    sptr<ISystemAbilityManager> systemAbilityManager
        = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ANSR_LOGE("Failed to get uid due to get systemAbilityManager is null.");
        return -1;
    }
    sptr<IRemoteObject> remoteObject  = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        ANSR_LOGE("Fail to get bundle manager proxy");
        return -1;
    }
    sptr<AppExecFwk::IBundleMgr> bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        ANSR_LOGE("Bundle mgr proxy is nullptr");
        return -1;
    }
    bundleMgr->GetApplicationInfo(bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, info);
    ANSR_LOGD("uid=%{public}d", info.uid);
    return static_cast<int32_t>(info.uid);
}

int32_t ReminderRequest::GetUserId(const int32_t &uid)
{
    int32_t userId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    ANSR_LOGD("userId=%{public}d", userId);
    return userId;
}

void ReminderRequest::AppendValuesBucket(const sptr<ReminderRequest> &reminder,
    const sptr<NotificationBundleOption> &bundleOption, NativeRdb::ValuesBucket &values)
{
    values.PutInt(REMINDER_ID, reminder->GetReminderId());
    values.PutString(PKG_NAME, bundleOption->GetBundleName());
    values.PutInt(USER_ID, reminder->GetUserId());
    values.PutInt(UID, reminder->GetUid());
    values.PutString(SYS_APP, reminder->IsSystemApp() ? "true" : "false");
    values.PutString(APP_LABEL, "");  // no use, compatible with old version.
    values.PutInt(REMINDER_TYPE, static_cast<int32_t>(reminder->GetReminderType()));
    values.PutLong(REMINDER_TIME, reminder->GetReminderTimeInMilli());
    values.PutLong(TRIGGER_TIME, reminder->GetTriggerTimeInMilli());
    values.PutLong(
        RTC_TRIGGER_TIME, reminder->GetTriggerTimeInMilli());  // no use, compatible with old version.
    values.PutLong(TIME_INTERVAL, reminder->GetTimeInterval());
    values.PutInt(SNOOZE_TIMES, reminder->GetSnoozeTimes());
    values.PutInt(DYNAMIC_SNOOZE_TIMES, reminder->GetSnoozeTimesDynamic());
    values.PutLong(RING_DURATION, reminder->GetRingDuration());
    values.PutString(IS_EXPIRED, reminder->IsExpired() ? "true" : "false");
    values.PutString(IS_ACTIVE, "");  // no use, compatible with old version.
    values.PutInt(STATE, reminder->GetState());
    values.PutString(ZONE_ID, "");  // no use, compatible with old version.
    values.PutString(HAS_SCHEDULED_TIMEOUT, "");  // no use, compatible with old version.
    values.PutString(ACTION_BUTTON_INFO, reminder->GetButtonInfo());
    values.PutString(CUSTOM_BUTTON_URI, reminder->GetCustomButtonUri());
    values.PutInt(SLOT_ID, reminder->GetSlotType());
    values.PutInt(NOTIFICATION_ID, reminder->GetNotificationId());
    values.PutString(TITLE, reminder->GetTitle());
    values.PutString(CONTENT, reminder->GetContent());
    values.PutString(SNOOZE_CONTENT, reminder->GetSnoozeContent());
    values.PutString(EXPIRED_CONTENT, reminder->GetExpiredContent());
    auto wantAgentInfo = reminder->GetWantAgentInfo();
    if (wantAgentInfo == nullptr) {
        std::string info = "null" + ReminderRequest::SEP_WANT_AGENT + "null" + ReminderRequest::SEP_WANT_AGENT + "null";
        values.PutString(AGENT, info);
    } else {
        std::string info = wantAgentInfo->pkgName + ReminderRequest::SEP_WANT_AGENT
            + wantAgentInfo->abilityName + ReminderRequest::SEP_WANT_AGENT + wantAgentInfo->uri;
        values.PutString(AGENT, info);
    }
    auto maxScreenWantAgentInfo = reminder->GetMaxScreenWantAgentInfo();
    if (maxScreenWantAgentInfo == nullptr) {
        std::string info = "null" + ReminderRequest::SEP_WANT_AGENT + "null";
        values.PutString(MAX_SCREEN_AGENT, info);
    } else {
        values.PutString(MAX_SCREEN_AGENT, maxScreenWantAgentInfo->pkgName
            + ReminderRequest::SEP_WANT_AGENT + maxScreenWantAgentInfo->abilityName);
    }
    values.PutString(TAP_DISMISSED, reminder->IsTapDismissed() ? "true" : "false");
    values.PutLong(AUTO_DELETED_TIME, reminder->GetAutoDeletedTime());
}

void ReminderRequest::InitDbColumns()
{
    AddColumn(REMINDER_ID, "INTEGER PRIMARY KEY", false);
    AddColumn(PKG_NAME, "TEXT NOT NULL", false);
    AddColumn(USER_ID, "INT NOT NULL", false);
    AddColumn(UID, "INT NOT NULL", false);
    AddColumn(SYS_APP, "TEXT NOT NULL", false);
    AddColumn(APP_LABEL, "TEXT", false);
    AddColumn(REMINDER_TYPE, "INT NOT NULL", false);
    AddColumn(REMINDER_TIME, "BIGINT NOT NULL", false);
    AddColumn(TRIGGER_TIME, "BIGINT NOT NULL", false);
    AddColumn(RTC_TRIGGER_TIME, "BIGINT NOT NULL", false);
    AddColumn(TIME_INTERVAL, "BIGINT NOT NULL", false);
    AddColumn(SNOOZE_TIMES, "INT NOT NULL", false);
    AddColumn(DYNAMIC_SNOOZE_TIMES, "INT NOT NULL", false);
    AddColumn(RING_DURATION, "BIGINT NOT NULL", false);
    AddColumn(IS_EXPIRED, "TEXT NOT NULL", false);
    AddColumn(IS_ACTIVE, "TEXT NOT NULL", false);
    AddColumn(STATE, "INT NOT NULL", false);
    AddColumn(ZONE_ID, "TEXT", false);
    AddColumn(HAS_SCHEDULED_TIMEOUT, "TEXT", false);
    AddColumn(ACTION_BUTTON_INFO, "TEXT", false);
    AddColumn(CUSTOM_BUTTON_URI, "TEXT", false);
    AddColumn(SLOT_ID, "INT", false);
    AddColumn(NOTIFICATION_ID, "INT NOT NULL", false);
    AddColumn(TITLE, "TEXT", false);
    AddColumn(CONTENT, "TEXT", false);
    AddColumn(SNOOZE_CONTENT, "TEXT", false);
    AddColumn(EXPIRED_CONTENT, "TEXT", false);
    AddColumn(AGENT, "TEXT", false);
    AddColumn(MAX_SCREEN_AGENT, "TEXT", false);
    AddColumn(TAP_DISMISSED, "TEXT", false);
    AddColumn(AUTO_DELETED_TIME, "BIGINT", false);
}

void ReminderRequest::AddColumn(
    const std::string &name, const std::string &type, const bool &isEnd)
{
    columns.push_back(name);
    if (!isEnd) {
        sqlOfAddColumns += name + " " + type + ", ";
    } else {
        sqlOfAddColumns += name + " " + type;
    }
}
}
}