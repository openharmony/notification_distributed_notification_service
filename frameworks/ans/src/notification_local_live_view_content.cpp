/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "notification_local_live_view_content.h"

#include <cstdint>
#include <string>                            // for basic_string, operator+
#include <algorithm>                         // for min

#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"                 // for json, basic_json<>::obje...
#include "notification_action_button.h"
#include "notification_basic_content.h"      // for NotificationBasicContent
#include "notification_capsule.h"
#include "notification_json_convert.h"
#include "notification_progress.h"
#include "notification_local_live_view_button.h"
#include "parcel.h"                          // for Parcel

namespace OHOS {
namespace Notification {

void NotificationLocalLiveViewContent::SetType(int32_t type)
{
    type_ = type;
}

void NotificationLocalLiveViewContent::SetCapsule(NotificationCapsule capsule)
{
    capsule_ = capsule;
}

void NotificationLocalLiveViewContent::SetButton(NotificationLocalLiveViewButton button)
{
    button_ = button;
}

void NotificationLocalLiveViewContent::SetProgress(NotificationProgress progress)
{
    progress_ = progress;
}

std::string NotificationLocalLiveViewContent::Dump()
{
    return "NotificationLocalLiveViewContent{ " + NotificationBasicContent::Dump() +
            ", type = " + std::to_string(type_) +
            ", capsule = " + capsule_.Dump() +
            ", button = " + button_.Dump() +
            ", progress = " + progress_.Dump() +
            " }";
}

bool NotificationLocalLiveViewContent::ToJson(nlohmann::json &jsonObject) const
{
    if (!NotificationBasicContent::ToJson(jsonObject)) {
        ANS_LOGE("Cannot convert basicContent to JSON");
        return false;
    }

    nlohmann::json capsuleObj;
    if (!NotificationJsonConverter::ConvertToJson(&capsule_, capsuleObj)) {
        ANS_LOGE("Cannot convert capsule to JSON");
        return false;
    }

    nlohmann::json buttonObj;
    if (!NotificationJsonConverter::ConvertToJson(&button_, buttonObj)) {
        ANS_LOGE("Cannot convert button to JSON");
        return false;
    }

    nlohmann::json progressObj;
    if (!NotificationJsonConverter::ConvertToJson(&progress_, progressObj)) {
        ANS_LOGE("Cannot convert progress to JSON");
        return false;
    }

    jsonObject["type"] = type_;
    jsonObject["capsule"] = capsuleObj;
    jsonObject["button"] = buttonObj;
    jsonObject["progress"] = progressObj;

    return true;
}

NotificationLocalLiveViewContent *NotificationLocalLiveViewContent::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pContent = new (std::nothrow) NotificationLocalLiveViewContent();
    if (pContent == nullptr) {
        ANS_LOGE("Failed to create localLiveViewContent instance");
        return nullptr;
    }

    pContent->ReadFromJson(jsonObject);

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("type") != jsonEnd) {
        pContent->type_ = jsonObject.at("type").get<int32_t>();
    }

    if (jsonObject.find("capsule") != jsonEnd) {
        auto capsuleObj = jsonObject.at("capsule");
        auto pCapsule = NotificationJsonConverter::ConvertFromJson<NotificationCapsule>(capsuleObj);
        if (pCapsule != nullptr) {
            pContent->capsule_ = *pCapsule;
            delete pCapsule;
            pCapsule = nullptr;
        }
    }

    if (jsonObject.find("button") != jsonEnd) {
        auto buttonObj = jsonObject.at("button");
        auto pButton = NotificationJsonConverter::ConvertFromJson<NotificationLocalLiveViewButton>(buttonObj);
        if (pButton != nullptr) {
            pContent->button_ = *pButton;
            delete pButton;
            pButton = nullptr;
        }
    }

    if (jsonObject.find("progress") != jsonEnd) {
        auto progressObj = jsonObject.at("progress");
        auto pProgress = NotificationJsonConverter::ConvertFromJson<NotificationProgress>(progressObj);
        if (pProgress != nullptr) {
            pContent->progress_ = *pProgress;
            delete pProgress;
            pProgress = nullptr;
        }
    }

    return pContent;
}

bool NotificationLocalLiveViewContent::Marshalling(Parcel &parcel) const
{
    if (!NotificationBasicContent::Marshalling(parcel)) {
        ANS_LOGE("Failed to write basic");
        return false;
    }

    if (!parcel.WriteInt32(type_)) {
        ANS_LOGE("Write type fail.");
        return false;
    }

    if (!parcel.WriteParcelable(&capsule_)) {
        ANS_LOGE("Failed to write capsule");
        return false;
    }

    if (!parcel.WriteParcelable(&button_)) {
        ANS_LOGE("Failed to write button");
        return false;
    }

    if (!parcel.WriteParcelable(&progress_)) {
        ANS_LOGE("Failed to write progress");
        return false;
    }

    return true;
}

NotificationLocalLiveViewContent *NotificationLocalLiveViewContent::Unmarshalling(Parcel &parcel)
{
    auto pContent = new (std::nothrow) NotificationLocalLiveViewContent();
    if ((pContent != nullptr) && !pContent->ReadFromParcel(parcel)) {
        delete pContent;
        pContent = nullptr;
    }

    return pContent;
}

bool NotificationLocalLiveViewContent::ReadFromParcel(Parcel &parcel)
{
    if (!NotificationBasicContent::ReadFromParcel(parcel)) {
        ANS_LOGE("Failed to read basic");
        return false;
    }

    if (!parcel.ReadInt32(type_)) {
        ANS_LOGE("Read type failed.");
        return false;
    }

    auto pCapsule = parcel.ReadParcelable<NotificationCapsule>();
    if (pCapsule == nullptr) {
        ANS_LOGE("Failed to read capsule");
        return false;
    }
    capsule_ = *pCapsule;
    delete pCapsule;
    pCapsule = nullptr;

    auto pButton = parcel.ReadParcelable<NotificationLocalLiveViewButton>();
    if (pButton == nullptr) {
        ANS_LOGE("Failed to read button");
        return false;
    }
    button_ = *pButton;
    delete pButton;
    pButton = nullptr;

    auto pProgress = parcel.ReadParcelable<NotificationProgress>();
    if (pProgress == nullptr) {
        ANS_LOGE("Failed to read capsule");
        return false;
    }
    progress_ = *pProgress;
    delete pProgress;
    pProgress = nullptr;

    return true;
}
}  // namespace Notification
}  // namespace OHOS