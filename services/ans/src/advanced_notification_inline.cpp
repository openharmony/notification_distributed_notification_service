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

#include <functional>
#include <iomanip>
#include <sstream>

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "os_account_manager.h"
#include "notification_preferences.h"


namespace OHOS {
namespace Notification {
inline std::string GetClientBundleName()
{
    std::string bundle;

    int32_t callingUid = IPCSkeleton::GetCallingUid();

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        bundle = bundleManager->GetBundleNameByUid(callingUid);
    }

    return bundle;
}

inline int64_t ResetSeconds(int64_t date)
{
    auto milliseconds = std::chrono::milliseconds(date);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(milliseconds);
    auto tp_minutes = std::chrono::time_point_cast<std::chrono::minutes>(tp);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(tp_minutes.time_since_epoch());
    return duration.count();
}

inline int64_t GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

inline tm GetLocalTime(time_t time)
{
    struct tm ret = {0};
    localtime_r(&time, &ret);
    return ret;
}

inline ErrCode AssignValidNotificationSlot(const std::shared_ptr<NotificationRecord> &record)
{
    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = record->request->GetSlotType();
    ErrCode result = NotificationPreferences::GetInstance().GetNotificationSlot(record->bundleOption, slotType, slot);
    if ((result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) ||
        (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST)) {
        slot = new (std::nothrow) NotificationSlot(slotType);
        if (slot == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot instance");
            return ERR_NO_MEMORY;
        }
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance().AddNotificationSlots(record->bundleOption, slots);
    }
    if (result == ERR_OK) {
        if (slot != nullptr && slot->GetEnable()) {
            record->slot = slot;
        } else {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED;
            ANS_LOGE("Type[%{public}d] slot enable closed", slotType);
        }
    }
    return result;
}

inline ErrCode CheckPictureSize(const sptr<NotificationRequest> &request)
{
    auto result = request->CheckImageSizeForContent();
    if (result != ERR_OK) {
        ANS_LOGE("Check image size failed.");
        return result;
    }

    if (request->CheckImageOverSizeForPixelMap(request->GetLittleIcon(), MAX_ICON_SIZE)) {
        return ERR_ANS_ICON_OVER_SIZE;
    }

    if (request->CheckImageOverSizeForPixelMap(request->GetBigIcon(), MAX_ICON_SIZE)) {
        return ERR_ANS_ICON_OVER_SIZE;
    }

    if (request->CheckImageOverSizeForPixelMap(request->GetOverlayIcon(), MAX_ICON_SIZE)) {
        return ERR_ANS_ICON_OVER_SIZE;
    }

    return ERR_OK;
}

inline void RemoveExpired(
    std::list<std::chrono::system_clock::time_point> &list, const std::chrono::system_clock::time_point &now)
{
    auto iter = list.begin();
    while (iter != list.end()) {
        if (abs(now - *iter) > std::chrono::seconds(1)) {
            iter = list.erase(iter);
        } else {
            break;
        }
    }
}
}  // namespace Notification
}  // namespace OHOS