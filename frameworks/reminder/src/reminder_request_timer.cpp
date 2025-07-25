/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "reminder_request_timer.h"

#include <chrono>
#include <cstdlib>

#include "ans_log_wrapper.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {
ReminderRequestTimer::ReminderRequestTimer(uint64_t countDownTimeInSeconds)
    : ReminderRequest(ReminderRequest::ReminderType::TIMER)
{
    CheckParamsValid(countDownTimeInSeconds);
    countDownTimeInSeconds_ = countDownTimeInSeconds;
    time_t now;  // unit is seconds.
    (void)time(&now);
    ReminderRequest::SetTriggerTimeInMilli(
        ReminderRequest::GetDurationSinceEpochInMilli(now) + countDownTimeInSeconds_ * ReminderRequest::MILLI_SECONDS);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Failed to get boot time due to TimeServiceClient is null.");
    } else {
        int64_t bootTimeMs = timer->GetBootTimeMs();
        if (bootTimeMs >= 0) {
            firstRealTimeInMilliSeconds_ = static_cast<uint64_t>(bootTimeMs);
        } else {
            ANSR_LOGE("Get boot time error.");
        }
    }
}

ReminderRequestTimer::ReminderRequestTimer(const ReminderRequestTimer &other) : ReminderRequest(other)
{
    firstRealTimeInMilliSeconds_ = other.firstRealTimeInMilliSeconds_;
    countDownTimeInSeconds_ = other.countDownTimeInSeconds_;
}

uint64_t ReminderRequestTimer::GetInitInfo() const
{
    return countDownTimeInSeconds_;
}

void ReminderRequestTimer::SetInitInfo(const uint64_t countDownTimeInSeconds)
{
    countDownTimeInSeconds_ = countDownTimeInSeconds;
}

uint64_t ReminderRequestTimer::PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext)
{
    ANSR_LOGD("called");
    return ReminderRequest::INVALID_LONG_LONG_VALUE;
}

bool ReminderRequestTimer::OnDateTimeChange()
{
    UpdateTimeInfo("onDateTimeChange");
    return false;
}

bool ReminderRequestTimer::OnTimeZoneChange()
{
    UpdateTimeInfo("onTimeZoneChange");
    return false;
}

bool ReminderRequestTimer::UpdateNextReminder()
{
    ANSR_LOGD("called");
    SetExpired(true);
    return false;
}

void ReminderRequestTimer::CheckParamsValid(const uint64_t countDownTimeInSeconds) const
{
    if (countDownTimeInSeconds == 0 || countDownTimeInSeconds >= (UINT64_MAX / ReminderRequest::MILLI_SECONDS)) {
        ANSR_LOGE("Illegal count down time, please check the description of the constructor");
        return;
    }
}

void ReminderRequestTimer::UpdateTimeInfo(const std::string &description)
{
    if (IsExpired()) {
        return;
    }

    ANSR_LOGD("%{public}s, update countdown time trigger time", description.c_str());
    time_t now;
    (void)time(&now);  // unit is seconds.
    whenToChangeSysTime_ = ReminderRequest::GetDurationSinceEpochInMilli(now);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Failed to updateTime info due to TimeServiceClient is null.");
        return;
    }
    int64_t bootTime = timer->GetBootTimeMs();
    if (bootTime < 0) {
        ANSR_LOGE("BootTime is illegal");
        return;
    }
    SetTriggerTimeInMilli(whenToChangeSysTime_ + countDownTimeInSeconds_ * MILLI_SECONDS -
        (static_cast<uint64_t>(bootTime) - firstRealTimeInMilliSeconds_));
}

bool ReminderRequestTimer::Marshalling(Parcel &parcel) const
{
    return WriteParcel(parcel);
}

bool ReminderRequestTimer::WriteParcel(Parcel &parcel) const
{
    if (ReminderRequest::WriteParcel(parcel)) {
        // write int
        WRITE_UINT64_RETURN_FALSE_LOG(parcel, firstRealTimeInMilliSeconds_, "firstRealTimeInMilliSeconds");
        WRITE_UINT64_RETURN_FALSE_LOG(parcel, countDownTimeInSeconds_, "countDownTimeInSeconds");
        return true;
    }
    return false;
}

ReminderRequestTimer *ReminderRequestTimer::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) ReminderRequestTimer();
    if (objptr == nullptr) {
        ANSR_LOGE("null objptr");
        return objptr;
    }
    if (!objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool ReminderRequestTimer::ReadFromParcel(Parcel &parcel)
{
    if (ReminderRequest::ReadFromParcel(parcel)) {
        // read int
        READ_UINT64_RETURN_FALSE_LOG(parcel, firstRealTimeInMilliSeconds_, "firstRealTimeInMilliSeconds");
        READ_UINT64_RETURN_FALSE_LOG(parcel, countDownTimeInSeconds_, "countDownTimeInSeconds");
        return true;
    }
    return false;
}
}
}
