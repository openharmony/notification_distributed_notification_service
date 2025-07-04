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

#include "notification_conversational_message.h"

#include "ans_log_wrapper.h"
#include "message_user.h"                         // for MessageUser
#include "nlohmann/json.hpp"                      // for json, basic_json<>:...
#include "notification_json_convert.h"            // for NotificationJsonCon...
#include "parcel.h"                               // for Parcel
#include "uri.h"                                  // for Uri

namespace OHOS {
namespace Notification {
NotificationConversationalMessage::NotificationConversationalMessage(
    const std::string &text, int64_t timestamp, const MessageUser &sender)
    : arrivedTime_(timestamp), text_(text), sender_(sender)
{}

std::string NotificationConversationalMessage::GetText() const
{
    return text_;
}

int64_t NotificationConversationalMessage::GetArrivedTime() const
{
    return arrivedTime_;
}

MessageUser NotificationConversationalMessage::GetSender() const
{
    return sender_;
}

void NotificationConversationalMessage::SetData(const std::string &mimeType, const std::shared_ptr<Uri> &uri)
{
    mimeType_ = mimeType;
    uri_ = uri;
}

std::string NotificationConversationalMessage::GetMimeType() const
{
    return mimeType_;
}

const std::shared_ptr<Uri> NotificationConversationalMessage::GetUri() const
{
    return uri_;
}

std::string NotificationConversationalMessage::Dump()
{
    return "NotificationConversationalMessage{ "
            "text = " + text_ +
            ", arrivedTime = " + std::to_string(arrivedTime_) +
            ", mimeType = " + mimeType_ +
            ", uri = " + (uri_ ? uri_->ToString() : "null") +
            ", sender = " + sender_.Dump() +
            " }";
}

bool NotificationConversationalMessage::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["arrivedTime"] = arrivedTime_;
    jsonObject["text"]        = text_;

    nlohmann::json userObj;
    if (!NotificationJsonConverter::ConvertToJson(&sender_, userObj)) {
        ANS_LOGE("Cannot convert sender to JSON");
        return false;
    }
    jsonObject["sender"] = userObj;

    jsonObject["uri"]      = uri_ ? uri_->ToString() : "";
    jsonObject["mimeType"] = mimeType_;

    return true;
}

NotificationConversationalMessage *NotificationConversationalMessage::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pMessage = new (std::nothrow) NotificationConversationalMessage();
    if (pMessage == nullptr) {
        ANS_LOGE("null pMessage");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("arrivedTime") != jsonEnd && jsonObject.at("arrivedTime").is_number_integer()) {
        pMessage->arrivedTime_ = jsonObject.at("arrivedTime").get<int64_t>();
    }

    if (jsonObject.find("text") != jsonEnd && jsonObject.at("text").is_string()) {
        pMessage->text_ = jsonObject.at("text").get<std::string>();
    }

    if (jsonObject.find("sender") != jsonEnd) {
        auto userObj = jsonObject.at("sender");
        auto pUser   = NotificationJsonConverter::ConvertFromJson<MessageUser>(userObj);
        if (pUser != nullptr) {
            pMessage->sender_ = *pUser;

            delete pUser;
            pUser = nullptr;
        }
    }

    if (jsonObject.find("uri") != jsonEnd && jsonObject.at("uri").is_string()) {
        auto uriStr = jsonObject.at("uri").get<std::string>();
        if (!uriStr.empty()) {
            pMessage->uri_ = std::make_shared<Uri>(uriStr);
        }
    }

    if (jsonObject.find("mimeType") != jsonEnd && jsonObject.at("mimeType").is_string()) {
        pMessage->mimeType_ = jsonObject.at("mimeType").get<std::string>();
    }

    return pMessage;
}

bool NotificationConversationalMessage::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt64(arrivedTime_)) {
        ANS_LOGE("Failed to write arrived time");
        return false;
    }

    if (!parcel.WriteString(text_)) {
        ANS_LOGE("Failed to write text");
        return false;
    }

    if (!parcel.WriteParcelable(&sender_)) {
        ANS_LOGE("Failed to write sender");
        return false;
    }

    auto valid = uri_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether uri is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(uri_.get())) {
            ANS_LOGE("Failed to write uri");
            return false;
        }
    }

    if (!parcel.WriteString(mimeType_)) {
        ANS_LOGE("Failed to write MIME type");
        return false;
    }

    return true;
}

NotificationConversationalMessage *NotificationConversationalMessage::Unmarshalling(Parcel &parcel)
{
    auto pMessage = new (std::nothrow) NotificationConversationalMessage();
    if ((pMessage != nullptr) && !pMessage->ReadFromParcel(parcel)) {
        delete pMessage;
        pMessage = nullptr;
    }

    return pMessage;
}

bool NotificationConversationalMessage::ReadFromParcel(Parcel &parcel)
{
    arrivedTime_ = parcel.ReadInt64();

    if (!parcel.ReadString(text_)) {
        ANS_LOGE("Failed to read text");
        return false;
    }

    auto pUser = parcel.ReadParcelable<MessageUser>();
    if (pUser == nullptr) {
        ANS_LOGE("null pUser");
        return false;
    }
    sender_ = *pUser;
    delete pUser;
    pUser = nullptr;

    auto valid = parcel.ReadBool();
    if (valid) {
        uri_ = std::shared_ptr<Uri>(parcel.ReadParcelable<Uri>());
        if (!uri_) {
            ANS_LOGE("Failed to read uri");
            return false;
        }
    }

    if (!parcel.ReadString(mimeType_)) {
        ANS_LOGE("Failed to read MIME type");
        return false;
    }

    return true;
}
}  // namespace Notification
}  // namespace OHOS
