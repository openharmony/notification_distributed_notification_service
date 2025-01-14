/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <memory>

#include "notification_config_parse.h"

#include "ans_log_wrapper.h"
#include "notification_trust_list.h"
#include "notification_slot.h"
#include "file_utils.h"

namespace OHOS {
namespace Notification {
NotificationConfigParse::NotificationConfigParse()
{
    if (!FileUtils::GetJsonByFilePath(NOTIFICAITON_CONFIG_FILE, notificationConfigJsons_)) {
        ANS_LOGE("Failed to get notification config file, fileName: %{public}s.", NOTIFICAITON_CONFIG_FILE);
    }
    defaultCurrentSlotReminder_ = {
        {NotificationConstant::SlotType::SOCIAL_COMMUNICATION, 0b111111},
        {NotificationConstant::SlotType::SERVICE_REMINDER, 0b111111},
        {NotificationConstant::SlotType::CONTENT_INFORMATION, 0b000000},
        {NotificationConstant::SlotType::OTHER, 0b000000},
        {NotificationConstant::SlotType::LIVE_VIEW, 0b111011},
        {NotificationConstant::SlotType::CUSTOMER_SERVICE, 0b110001},
        {NotificationConstant::SlotType::EMERGENCY_INFORMATION, 0b111111}
    };
}

bool NotificationConfigParse::GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const
{
    if (notificationConfigJsons_.size() <= 0) {
        ANS_LOGE("Failed to get config json cause empty notificationConfigJsons.");
        return false;
    }
    bool ret = false;
    std::for_each(notificationConfigJsons_.rbegin(), notificationConfigJsons_.rend(),
        [&keyCheck, &configJson, &ret](const nlohmann::json &json) {
        if (keyCheck.find("/") == std::string::npos && json.contains(keyCheck)) {
            configJson = json;
            ret = true;
        }

        if (keyCheck.find("/") != std::string::npos) {
            nlohmann::json::json_pointer keyCheckPoint(keyCheck);
            if (json.contains(keyCheckPoint)) {
                configJson = json;
                ret = true;
            }
        }
    });
    if (!ret) {
        ANS_LOGE("Cannot find keyCheck: %{public}s in notificationConfigJsons.", keyCheck.c_str());
    }
    return ret;
}

bool NotificationConfigParse::GetCurrentSlotReminder(
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const
{
    nlohmann::json root;
    std::string slotJsonPoint = "/";
    slotJsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    slotJsonPoint.append("/");
    slotJsonPoint.append(CFG_KEY_SLOT_TYPE_REMINDER);
    if (!GetConfigJson(slotJsonPoint, root)) {
        return false;
    }

    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("GetCurrentSlotReminder failed as can not find notificationService.");
        return false;
    }
    nlohmann::json currentDeviceRemindJson = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_SLOT_TYPE_REMINDER];
    if (currentDeviceRemindJson.is_null() || !currentDeviceRemindJson.is_array() || currentDeviceRemindJson.empty()) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentDeviceReminder json.");
        return false;
    }
    for (auto &reminderFilterSlot : currentDeviceRemindJson) {
        NotificationConstant::SlotType slotType;
        if (reminderFilterSlot.find(CFG_KEY_NAME) == reminderFilterSlot.end() ||
            reminderFilterSlot[CFG_KEY_NAME].is_null() ||
            !reminderFilterSlot[CFG_KEY_NAME].is_string() ||
            !NotificationSlot::GetSlotTypeByString(reminderFilterSlot[CFG_KEY_NAME].get<std::string>(), slotType)) {
            continue;
        }

        std::shared_ptr<NotificationFlags> reminderFlags;
        if (reminderFilterSlot.find(CFG_KEY_REMINDER_FLAGS) == reminderFilterSlot.end() ||
            reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].is_null() ||
            !reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].is_string() ||
            !NotificationFlags::GetReminderFlagsByString(
                reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].get<std::string>(), reminderFlags)) {
            continue;
        }
        currentSlotReminder[slotType] = reminderFlags;
    }
    if (currentSlotReminder.size() <= 0) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentSlotReminder size.");
        return false;
    }
    return true;
}

uint32_t NotificationConfigParse::GetConfigSlotReminderModeByType(NotificationConstant::SlotType slotType) const
{
    static std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> configSlotsReminder;
    if (configSlotsReminder.empty()) {
        GetCurrentSlotReminder(configSlotsReminder);
    }

    auto iter = configSlotsReminder.find(slotType);
    if (iter != configSlotsReminder.end()) {
        return iter->second->GetReminderFlags();
    }

    auto defaultIter = defaultCurrentSlotReminder_.find(slotType);
    if (defaultIter != defaultCurrentSlotReminder_.end()) {
        return defaultIter->second;
    }

    return 0;
}

uint32_t NotificationConfigParse::GetConfigSlotReminderModeByType(NotificationConstant::SlotType slotType,
    const sptr<NotificationBundleOption> &bundleOption) const
{
    uint32_t reminderFlags = GetConfigSlotReminderModeByType(slotType);
    if (DelayedSingleton<NotificationTrustList>::GetInstance()->IsSlotFlagsTrustlistAsBundle(bundleOption)) {
        return reminderFlags & 0b111111;
    }
    return reminderFlags;
}

void NotificationConfigParse::GetFlowCtrlConfigFromCCM(FlowControlThreshold &threshold)
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    if (!GetConfigJson(JsonPoint, root)) {
        ANS_LOGE("Failed to get JsonPoint CCM config file");
        return;
    }
    if (!root.contains(CFG_KEY_NOTIFICATION_SERVICE)) {
        ANS_LOGW("GetFlowCtrlConfigFromCCM not found jsonKey");
        return;
    }
    nlohmann::json affects = root[CFG_KEY_NOTIFICATION_SERVICE];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetFlowCtrlConfigFromCCM failed as invalid ccmFlowCtrlConfig json");
        return;
    }
    if (affects.contains(CFG_KEY_MAX_CREATE_NUM_PERSECOND)) {
        threshold.maxCreateNumPerSecond = affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND];
    }

    if (affects.contains(CFG_KEY_MAX_UPDATE_NUM_PERSECOND)) {
        threshold.maxUpdateNumPerSecond = affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND];
    }

    if (affects.contains(CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP)) {
        threshold.maxCreateNumPerSecondPerApp = affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP];
    }

    if (affects.contains(CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP)) {
        threshold.maxUpdateNumPerSecondPerApp = affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP];
    }

    ANS_LOGI("GetFlowCtrlConfigFromCCM success");
}
void NotificationConfigParse::GetReportTrustListConfig()
{
    nlohmann::json root;
    std::string reportJsonPoint = "/";
    reportJsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    reportJsonPoint.append("/");
    reportJsonPoint.append(CFG_KEY_DFX_NORMAL_EVENT);
    if (!GetConfigJson(reportJsonPoint, root)) {
        return;
    }
    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("Failed to get JsonPoint CCM config file");
        return;
    }

    nlohmann::json reportTrustList = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_DFX_NORMAL_EVENT];
    if (reportTrustList.is_null() || reportTrustList.empty() || !reportTrustList.is_array()) {
        ANS_LOGE("GetReportTrustListConfig failed as invalid dfx_normal_events json.");
        return;
    }
    for (auto &reportTrust : reportTrustList) {
        reporteTrustSet_.emplace(reportTrust);
    }
    return;
}


bool NotificationConfigParse::IsReportTrustList(const std::string& bundleName) const
{
    return reporteTrustSet_.count(bundleName);
}
} // namespace Notification
} // namespace OHOS
