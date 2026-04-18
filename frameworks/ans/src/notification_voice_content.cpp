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

#include "notification_voice_content.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

NotificationVoiceContent::NotificationVoiceContent(const NotificationVoiceContent &other)
{
    textContent_ = other.GetTextContent();
}

void NotificationVoiceContent::SetTextContent(const std::string &textContent)
{
    textContent_ = textContent;
}

std::string NotificationVoiceContent::GetTextContent() const
{
    return textContent_;
}

std::string NotificationVoiceContent::Dump()
{
    return "NotificationVoiceContent{ textContent = " + textContent_ + " }";
}

bool NotificationVoiceContent::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(textContent_)) {
        ANS_LOGE("Failed to write textContent");
        return false;
    }

    return true;
}

NotificationVoiceContent *NotificationVoiceContent::Unmarshalling(Parcel &parcel)
{
    auto voiceContent = new (std::nothrow) NotificationVoiceContent();
    if (voiceContent == nullptr) {
        ANS_LOGE("Failed to create NotificationVoiceContent");
        return nullptr;
    }

    if (!voiceContent->ReadFromParcel(parcel)) {
        delete voiceContent;
        return nullptr;
    }

    return voiceContent;
}

bool NotificationVoiceContent::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(textContent_)) {
        ANS_LOGE("Failed to read textContent");
        return false;
    }

    return true;
}

}  // namespace Notification
}  // namespace OHOS
