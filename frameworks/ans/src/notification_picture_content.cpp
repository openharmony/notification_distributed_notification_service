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

#include "notification_picture_content.h"
#include "ans_image_util.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
void NotificationPictureContent::SetExpandedTitle(const std::string &exTitle)
{
    expandedTitle_ = exTitle;
}

std::string NotificationPictureContent::GetExpandedTitle() const
{
    return expandedTitle_;
}

void NotificationPictureContent::SetBriefText(const std::string &briefText)
{
    briefText_ = briefText;
}

std::string NotificationPictureContent::GetBriefText() const
{
    return briefText_;
}

void NotificationPictureContent::SetBigPicture(const std::shared_ptr<Media::PixelMap> &bigPicture)
{
    bigPicture_ = bigPicture;
}

const std::shared_ptr<Media::PixelMap> NotificationPictureContent::GetBigPicture() const
{
    return bigPicture_;
}

std::string NotificationPictureContent::Dump()
{
    return "NotificationPictureContent{ " + NotificationBasicContent::Dump() +
            ", briefText = " + briefText_ +
            ", expandedTitle = " + expandedTitle_ +
            ", bigPicture = " + (bigPicture_ ? "not null" : "null") +
            " }";
}

bool NotificationPictureContent::ToJson(nlohmann::json &jsonObject) const
{
    if (!NotificationBasicContent::ToJson(jsonObject)) {
        ANS_LOGE("Cannot convert basicContent to JSON");
        return false;
    }

    jsonObject["expandedTitle"] = expandedTitle_;
    jsonObject["briefText"]     = briefText_;
    jsonObject["bigPicture"]    = AnsImageUtil::PackImage(bigPicture_);

    return true;
}

NotificationPictureContent *NotificationPictureContent::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pContent = new (std::nothrow) NotificationPictureContent();
    if (pContent == nullptr) {
        ANS_LOGE("null pContent");
        return nullptr;
    }

    pContent->ReadFromJson(jsonObject);

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("expandedTitle") != jsonEnd && jsonObject.at("expandedTitle").is_string()) {
        ANS_LOGD("Find expandedTitle success");
        pContent->expandedTitle_ = jsonObject.at("expandedTitle").get<std::string>();
    }

    if (jsonObject.find("briefText") != jsonEnd && jsonObject.at("briefText").is_string()) {
        pContent->briefText_ = jsonObject.at("briefText").get<std::string>();
    }

    if (jsonObject.find("bigPicture") != jsonEnd && jsonObject.at("bigPicture").is_string()) {
        auto picStr           = jsonObject.at("bigPicture").get<std::string>();
        pContent->bigPicture_ = AnsImageUtil::UnPackImage(picStr);
    }

    return pContent;
}

bool NotificationPictureContent::Marshalling(Parcel &parcel) const
{
    if (!NotificationBasicContent::Marshalling(parcel)) {
        ANS_LOGE("Failed to write basic");
        return false;
    }

    if (!parcel.WriteString(expandedTitle_)) {
        ANS_LOGE("Failed to write expanded title");
        return false;
    }

    if (!parcel.WriteString(briefText_)) {
        ANS_LOGE("Failed to write brief text");
        return false;
    }

    auto valid = bigPicture_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether bigPicture is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(bigPicture_.get())) {
            ANS_LOGE("Failed to write bigPicture");
            return false;
        }
    }

    return true;
}

NotificationPictureContent *NotificationPictureContent::Unmarshalling(Parcel &parcel)
{
    auto pContent = new (std::nothrow) NotificationPictureContent();
    if ((pContent != nullptr) && !pContent->ReadFromParcel(parcel)) {
        delete pContent;
        pContent = nullptr;
    }

    return pContent;
}

bool NotificationPictureContent::ReadFromParcel(Parcel &parcel)
{
    if (!NotificationBasicContent::ReadFromParcel(parcel)) {
        ANS_LOGE("Failed to read basic");
        return false;
    }

    if (!parcel.ReadString(expandedTitle_)) {
        ANS_LOGE("Failed to read expanded title");
        return false;
    }

    if (!parcel.ReadString(briefText_)) {
        ANS_LOGE("Failed to read brief text");
        return false;
    }

    auto valid = parcel.ReadBool();
    if (valid) {
        bigPicture_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!bigPicture_) {
            ANS_LOGE("Failed to read bigPicture");
            return false;
        }
    }

    return true;
}
}  // namespace Notification
}  // namespace OHOS
