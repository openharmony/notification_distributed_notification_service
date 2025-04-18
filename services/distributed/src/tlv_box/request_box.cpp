/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "request_box.h"

#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "distributed_local_config.h"

namespace OHOS {
namespace Notification {

NotifticationRequestBox::NotifticationRequestBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(PUBLISH_NOTIFICATION);
}

NotifticationRequestBox::NotifticationRequestBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool NotifticationRequestBox::SetNotificationHashCode(const std::string& hasdCode)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hasdCode));
}

bool NotifticationRequestBox::SetSlotType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_SLOT_TYPE, type));
}

bool NotifticationRequestBox::SetContentType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT_TYPE, type));
}

bool NotifticationRequestBox::SetReminderFlag(int32_t flag)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_REMINDERFLAG, flag));
}

bool NotifticationRequestBox::SetCreatorBundleName(const std::string& bundleName)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(BUNDLE_NAME, bundleName));
}

bool NotifticationRequestBox::SetNotificationTitle(const std::string& title)
{
    if (box_ == nullptr) {
        return false;
    }
    uint32_t maxLength = static_cast<uint32_t>(DistributedLocalConfig::GetInstance().GetTitleLength());
    if (title.size() > maxLength) {
        ANS_LOGI("SetNotificationTitle truncate %{public}d %{public}d", (int32_t)(title.size()), (int32_t)(maxLength));
        std::string subTitle =  title.substr(0, maxLength);
        ANS_LOGI("SetNotificationTitle truncate %{public}s %{public}s", subTitle.c_str(), title.c_str());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_TITLE, subTitle));
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_TITLE, title));
}

bool NotifticationRequestBox::SetNotificationText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    uint32_t maxLength = static_cast<uint32_t>(DistributedLocalConfig::GetInstance().GetContentLength());
    if (text.size() > maxLength) {
        ANS_LOGI("SetNotificationText truncate %{public}d %{public}d", (int32_t)(text.size()), (int32_t)(maxLength));
        std::string subText =  text.substr(0, maxLength);
        ANS_LOGI("SetNotificationTitle truncate %{public}s %{public}s", subText.c_str(), text.c_str());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT, subText));
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT, text));
}

bool NotifticationRequestBox::SetNotificationAdditionalText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_ADDITIONAL_TEXT, text));
}

bool NotifticationRequestBox::SetNotificationBriefText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BRIEF_TEXT, text));
}

bool NotifticationRequestBox::SetNotificationExpandedTitle(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_EXPANDED_TITLE, text));
}

bool NotifticationRequestBox::SetNotificationLongText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_LONG_TITLE, text));
}

bool NotifticationRequestBox::SetNotificationAllLines(const std::vector<std::string>& allLines)
{
    return true;
}

bool NotifticationRequestBox::SetNotificationBigPicture(const std::shared_ptr<Media::PixelMap>& bigPicture)
{
    return true;
}

bool NotifticationRequestBox::SetNotificationActionName(const std::string& actionName)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_BUTTON_NAME, actionName));
}

bool NotifticationRequestBox::SetNotificationUserInput(const std::string& userInput)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_USER_INPUT, userInput));
}

bool NotifticationRequestBox::SetBigIcon(const std::shared_ptr<Media::PixelMap>& bigIcon)
{
    if (box_ == nullptr) {
        return false;
    }

    std::string copyIcon = AnsImageUtil::PackImage(bigIcon);
    auto copyPixelMap = AnsImageUtil::UnPackImage(copyIcon);
    if (!AnsImageUtil::ImageScale(copyPixelMap, DEFAULT_ICON_WITHE, DEFAULT_ICON_HEIGHT)) {
        return false;
    }
    std::string icon = AnsImageUtil::PackImage(copyPixelMap);
    ANS_LOGI("SetBigIcon %{public}d, %{public}d", (int32_t)(copyIcon.size()), (int32_t)(icon.size()));
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BIG_ICON, icon));
}

bool NotifticationRequestBox::SetOverlayIcon(const std::shared_ptr<Media::PixelMap>& overlayIcon)
{
    if (box_ == nullptr) {
        return false;
    }
    std::string copyIcon = AnsImageUtil::PackImage(overlayIcon);
    auto copyPixelMap = AnsImageUtil::UnPackImage(copyIcon);
    if (!AnsImageUtil::ImageScale(copyPixelMap, DEFAULT_ICON_WITHE, DEFAULT_ICON_HEIGHT)) {
        return false;
    }
    std::string icon = AnsImageUtil::PackImage(copyPixelMap);
    ANS_LOGI("SetOverlayIcon %{public}d, %{public}d", (int32_t)(copyIcon.size()), (int32_t)(icon.size()));
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_OVERLAY_ICON, icon));
}

bool NotifticationRequestBox::SetCommonLiveView(const std::vector<uint8_t>& byteSequence)
{
    if (box_ == nullptr) {
        return false;
    }
    const unsigned char* begin = byteSequence.data();
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_COMMON_LIVEVIEW,
        begin, byteSequence.size()));
}

bool NotifticationRequestBox::SetFinishTime(int64_t time)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(FINISH_DEADLINE_TIME, time));
}

bool NotifticationRequestBox::SetAutoDeleteTime(int64_t time)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(AUTO_DELETE_TIME, time));
}

bool NotifticationRequestBox::GetNotificationHashCode(std::string& hasdCode) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hasdCode);
}

bool NotifticationRequestBox::GetSlotType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_SLOT_TYPE, type);
}

bool NotifticationRequestBox::GetContentType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_CONTENT_TYPE, type);
}

bool NotifticationRequestBox::GetCreatorBundleName(std::string& bundleName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(BUNDLE_NAME, bundleName);
}

bool NotifticationRequestBox::GetReminderFlag(int32_t& flag) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_REMINDERFLAG, flag);
}

bool NotifticationRequestBox::GetNotificationTitle(std::string& title) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_TITLE, title);
}

bool NotifticationRequestBox::GetNotificationText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_CONTENT, text);
}

bool NotifticationRequestBox::GetNotificationAdditionalText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_ADDITIONAL_TEXT, text);
}

bool NotifticationRequestBox::GetNotificationBriefText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_BRIEF_TEXT, text);
}

bool NotifticationRequestBox::GetNotificationExpandedTitle(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_EXPANDED_TITLE, text);
}

bool NotifticationRequestBox::GetNotificationLongText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_LONG_TITLE, text);
}

bool NotifticationRequestBox::GetNotificationAllLines(std::vector<std::string>& allLines) const
{
    return true;
}

bool NotifticationRequestBox::GetNotificationBigPicture(std::shared_ptr<Media::PixelMap>& bigPicture) const
{
    return true;
}

bool NotifticationRequestBox::GetNotificationActionName(std::string& actionName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_BUTTON_NAME, actionName);
}

bool NotifticationRequestBox::GetNotificationUserInput(std::string& userInput) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_USER_INPUT, userInput);
}

bool NotifticationRequestBox::GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::string bigIconContent;
    if (!box_->GetStringValue(NOTIFICATION_BIG_ICON, bigIconContent)) {
        return false;
    }
    ANS_LOGI("GetBigIcon %{public}d", (int32_t)(bigIconContent.size()));
    bigIcon = AnsImageUtil::UnPackImage(bigIconContent);
    return true;
}

bool NotifticationRequestBox::GetOverlayIcon(std::shared_ptr<Media::PixelMap>& overlayIcon) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::string overlayContent;
    if (!box_->GetStringValue(NOTIFICATION_OVERLAY_ICON, overlayContent)) {
        return false;
    }
    ANS_LOGI("GetOverlayIcon %{public}d", (int32_t)(overlayContent.size()));
    overlayIcon = AnsImageUtil::UnPackImage(overlayContent);
    return true;
}

bool NotifticationRequestBox::GetCommonLiveView(std::vector<uint8_t>& byteSequence) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetBytes(NOTIFICATION_COMMON_LIVEVIEW, byteSequence);
}

bool NotifticationRequestBox::GetFinishTime(int64_t& time) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt64Value(FINISH_DEADLINE_TIME, time);
}

bool NotifticationRequestBox::GetAutoDeleteTime(int64_t& time) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt64Value(AUTO_DELETE_TIME, time);
}
}
}
