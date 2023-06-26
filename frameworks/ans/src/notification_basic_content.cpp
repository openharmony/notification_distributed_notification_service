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

#include "notification_basic_content.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
NotificationBasicContent::~NotificationBasicContent()
{}

void NotificationBasicContent::SetAdditionalText(const std::string &additionalText)
{
    additionalText_ = additionalText;
}

std::string NotificationBasicContent::GetAdditionalText() const
{
    return additionalText_;
}

void NotificationBasicContent::SetText(const std::string &text)
{
    text_ = text;
}

std::string NotificationBasicContent::GetText() const
{
    return text_;
}

void NotificationBasicContent::SetTitle(const std::string &title)
{
    title_ = title;
}

std::string NotificationBasicContent::GetTitle() const
{
    return title_;
}

std::string NotificationBasicContent::Dump()
{
    return "title = " + title_ + ", text = " + text_ + ", additionalText = " + additionalText_;
}

bool NotificationBasicContent::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["text"]           = text_;
    jsonObject["title"]          = title_;
    jsonObject["additionalText"] = additionalText_;

    return true;
}

void NotificationBasicContent::ReadFromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("text") != jsonEnd && jsonObject.at("text").is_string()) {
        text_ = jsonObject.at("text").get<std::string>();
    }

    if (jsonObject.find("title") != jsonEnd && jsonObject.at("title").is_string()) {
        title_ = jsonObject.at("title").get<std::string>();
    }

    if (jsonObject.find("additionalText") != jsonEnd && jsonObject.at("additionalText").is_string()) {
        additionalText_ = jsonObject.at("additionalText").get<std::string>();
    }
}

bool NotificationBasicContent::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(text_)) {
        ANS_LOGE("Failed to write text");
        return false;
    }

    if (!parcel.WriteString(title_)) {
        ANS_LOGE("Failed to write title");
        return false;
    }

    if (!parcel.WriteString(additionalText_)) {
        ANS_LOGE("Failed to write additional text");
        return false;
    }

    return true;
}

bool NotificationBasicContent::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(text_)) {
        ANS_LOGE("Failed to read text");
        return false;
    }

    if (!parcel.ReadString(title_)) {
        ANS_LOGE("Failed to read title");
        return false;
    }

    if (!parcel.ReadString(additionalText_)) {
        ANS_LOGE("Failed to read additional text");
        return false;
    }

    return true;
}
}  // namespace Notification
}  // namespace OHOS
