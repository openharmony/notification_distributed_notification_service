/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "smart_reminder_center.h"

#include "ans_log_wrapper.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_preferences.h"
#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#endif
#include "notification_local_live_view_content.h"
#include "notification_preferences.h"
#include "screenlock_manager.h"

namespace OHOS {
namespace Notification {
using namespace std;
SmartReminderCenter::SmartReminderCenter()
{
    if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetCurrentSlotReminder(currentReminderMethods_)) {
        return;
    }
    GetMultiDeviceReminder();
}

void SmartReminderCenter::GetMultiDeviceReminder()
{
    nlohmann::json root;
    string multiJsonPoint = "/";
    multiJsonPoint.append(NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE);
    multiJsonPoint.append("/");
    multiJsonPoint.append(MULTI_DEVICE_REMINDER);
    if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetConfigJson(multiJsonPoint, root)) {
        ANS_LOGI("Failed to get multiDeviceReminder CCM config file.");
        return;
    }

    nlohmann::json multiDeviceRemindJson =
        root[NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE][MULTI_DEVICE_REMINDER];
    if (multiDeviceRemindJson.is_null() || !multiDeviceRemindJson.is_array() || multiDeviceRemindJson.empty()) {
        ANS_LOGI("GetMultiDeviceReminder failed as invalid multiDeviceReminder json.");
        return;
    }
    reminderMethods_.clear();
    for (auto &singleDeviceRemindJson : multiDeviceRemindJson) {
        if (singleDeviceRemindJson.is_null() || !singleDeviceRemindJson.is_object()) {
            continue;
        }
        string deviceType;
        if (singleDeviceRemindJson[ReminderAffected::DEVICE_TYPE].is_null() ||
            !singleDeviceRemindJson[ReminderAffected::DEVICE_TYPE].is_string() ||
            singleDeviceRemindJson[REMINDER_FILTER_DEVICE].is_null() ||
            !singleDeviceRemindJson[REMINDER_FILTER_DEVICE].is_array() ||
            singleDeviceRemindJson[REMINDER_FILTER_DEVICE].empty()) {
            continue;
        }
        deviceType = singleDeviceRemindJson[ReminderAffected::DEVICE_TYPE].get<string>();
        ParseReminderFilterDevice(singleDeviceRemindJson[REMINDER_FILTER_DEVICE], deviceType);
    }

    if (reminderMethods_.size() <= 0) {
        ANS_LOGI("GetMultiDeviceReminder failed as Invalid reminderMethods size.");
    }
}

void SmartReminderCenter::ParseReminderFilterDevice(const nlohmann::json &root, const string &deviceType)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice;
    for (auto &reminderFilterDeviceJson : root) {
        NotificationConstant::SlotType slotType;
        if (reminderFilterDeviceJson[SLOT_TYPE].is_null() ||
            !reminderFilterDeviceJson[SLOT_TYPE].is_string() ||
            !NotificationSlot::GetSlotTypeByString(reminderFilterDeviceJson[SLOT_TYPE].get<std::string>(), slotType) ||
            reminderFilterDeviceJson[REMINDER_FILTER_SLOT].is_null() ||
            !reminderFilterDeviceJson[REMINDER_FILTER_SLOT].is_array() ||
            reminderFilterDeviceJson[REMINDER_FILTER_SLOT].empty()) {
            continue;
        }
        ParseReminderFilterSlot(reminderFilterDeviceJson[REMINDER_FILTER_SLOT],
            to_string(static_cast<int32_t>(slotType)), reminderFilterDevice);
    }
    if (reminderFilterDevice.size() > 0) {
        reminderMethods_[deviceType] = move(reminderFilterDevice);
    } else {
        ANS_LOGI("ParseReminderFilterDevice failed as Invalid reminderFilterDevice size. deviceType = %{public}s.",
            deviceType.c_str());
    }
}

void SmartReminderCenter::ParseReminderFilterSlot(
    const nlohmann::json &root,
    const string &notificationType,
    map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const
{
    vector<shared_ptr<ReminderAffected>> reminderFilterSlot;
    for (auto &reminderFilterSlotJson : root) {
        NotificationContent::Type contentType;
        if (!reminderFilterSlotJson[CONTENT_TYPE].is_null() &&
            reminderFilterSlotJson[CONTENT_TYPE].is_string() &&
            NotificationContent::GetContentTypeByString(
                reminderFilterSlotJson[CONTENT_TYPE].get<std::string>(), contentType) &&
            !reminderFilterSlotJson[REMINDER_FILTER_CONTENT].is_null() &&
            reminderFilterSlotJson[REMINDER_FILTER_CONTENT].is_array() &&
            !reminderFilterSlotJson[REMINDER_FILTER_CONTENT].empty()) {
            string localNotificationType = notificationType;
            localNotificationType.append("#");
            localNotificationType.append(to_string(static_cast<int32_t>(contentType)));
            ParseReminderFilterContent(
                reminderFilterSlotJson[REMINDER_FILTER_CONTENT], localNotificationType, reminderFilterDevice);
            continue;
        }
        shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
        if (reminderAffected->FromJson(reminderFilterSlotJson)) {
            reminderFilterSlot.push_back(reminderAffected);
        }
    }
    if (reminderFilterSlot.size() > 0) {
        reminderFilterDevice[notificationType] = move(reminderFilterSlot);
    }
}

void SmartReminderCenter::ParseReminderFilterContent(
    const nlohmann::json &root,
    const string &notificationType,
    map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const
{
    vector<shared_ptr<ReminderAffected>> reminderFilterContent;
    for (auto &reminderFilterContentJson : root) {
        if (!reminderFilterContentJson[TYPE_CODE].is_null() &&
            reminderFilterContentJson[TYPE_CODE].is_number() &&
            !reminderFilterContentJson[REMINDER_FILTER_CODE].is_null() &&
            reminderFilterContentJson[REMINDER_FILTER_CODE].is_array() &&
            !reminderFilterContentJson[REMINDER_FILTER_CODE].empty()) {
            int32_t typeCode = reminderFilterContentJson[TYPE_CODE].get<int32_t>();
            string localNotificationType = notificationType;
            localNotificationType.append("#");
            localNotificationType.append(to_string(typeCode));
            ParseReminderFilterCode(
                reminderFilterContentJson[REMINDER_FILTER_CODE], localNotificationType, reminderFilterDevice);
            continue;
        }
        shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
        if (reminderAffected->FromJson(reminderFilterContentJson)) {
            reminderFilterContent.push_back(reminderAffected);
        }
    }
    if (reminderFilterContent.size() > 0) {
        reminderFilterDevice[notificationType] = move(reminderFilterContent);
    }
}

void SmartReminderCenter::ParseReminderFilterCode(
    const nlohmann::json &root,
    const string &notificationType,
    map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const
{
    vector<shared_ptr<ReminderAffected>> reminderFilterCode;
    for (auto &reminderFilterCodeJson : root) {
        shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
        if (reminderAffected->FromJson(reminderFilterCodeJson)) {
            reminderFilterCode.push_back(reminderAffected);
        }
    }
    if (reminderFilterCode.size() > 0) {
        reminderFilterDevice[notificationType] = move(reminderFilterCode);
    }
}

void SmartReminderCenter::ReminderDecisionProcess(const sptr<NotificationRequest> &request) const
{
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    NotificationConstant::SlotType slotType = request->GetSlotType();
    auto iter = currentReminderMethods_.find(slotType);
    if (iter != currentReminderMethods_.end()) {
        // Only config file can set reminder open now. Otherwise, change iter->second to 11111
        (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = iter->second;
    }
    for (auto &reminderMethod : reminderMethods_) {
        HandleReminderMethods(
            reminderMethod.first, reminderMethod.second, request, notificationFlagsOfDevices);
    }
    request->SetDeviceFlags(notificationFlagsOfDevices);
}

void SmartReminderCenter::HandleReminderMethods(
    const string &deviceType,
    const map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice,
    const sptr<NotificationRequest> &request,
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices) const
{
    vector<shared_ptr<ReminderAffected>> reminderAffecteds;
    GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);
    if (reminderAffecteds.size() <= 0) {
        return;
    }
    bitset<DistributedDeviceStatus::STATUS_SIZE> bitStatus;
    GetDeviceStatusByType(deviceType, bitStatus);
    bool enabledAffectedBy = true;
    bool tempEnable = true;
    if (NotificationPreferences::GetInstance().IsSmartReminderEnabled(deviceType, tempEnable) != ERR_OK ||
        !tempEnable) {
        enabledAffectedBy = false;
    }
    int uid = IPCSkeleton::GetCallingUid();
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption(request->GetOwnerBundleName(), uid);
    if (NotificationPreferences::GetInstance().IsDistributedEnabledByBundle(
        bundleOption, deviceType, tempEnable) != ERR_OK || !tempEnable) {
        enabledAffectedBy = false;
    }
    delete bundleOption;
    bundleOption = nullptr;
    if (!NotificationSubscriberManager::GetInstance()->GetIsEnableEffectedRemind()) {
        enabledAffectedBy = false;
    }

    for (auto &reminderAffected : reminderAffecteds) {
        if (!CompareStatus(reminderAffected->status_, bitStatus)) {
            continue;
        }
        if (reminderAffected->affectedBy_.size() <= 0) {
            (*notificationFlagsOfDevices)[deviceType] = reminderAffected->reminderFlags_;
            continue;
        }
        if (enabledAffectedBy && HandleAffectedReminder(deviceType, reminderAffected, notificationFlagsOfDevices)) {
            break;
        }
    }
}

bool SmartReminderCenter::HandleAffectedReminder(
    const string &deviceType,
    const shared_ptr<ReminderAffected> &reminderAffected,
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices) const
{
    bool ret = true;
    for (auto &affectedBy : reminderAffected->affectedBy_) {
        bitset<DistributedDeviceStatus::STATUS_SIZE> bitStatus;
        GetDeviceStatusByType(affectedBy.first, bitStatus);
        if (!CompareStatus(affectedBy.second, bitStatus)) {
            ret = false;
            break;
        }
    }
    if (ret) {
        (*notificationFlagsOfDevices)[deviceType] = reminderAffected->reminderFlags_;
    }
    return ret;
}

bool SmartReminderCenter::CompareStatus(
    const string &status, const bitset<DistributedDeviceStatus::STATUS_SIZE> &bitStatus) const
{
    if (status.size() <= 0) {
        return true;
    }
    // bitset.to_string() and config is reverse, bit[0] is behind
    string localStatus = status;
    reverse(localStatus.begin(), localStatus.end());
    for (int32_t seq = 0; seq < DistributedDeviceStatus::STATUS_SIZE; seq++) {
        if (localStatus[seq] != ReminderAffected::STATUS_DEFAULT && bitStatus[seq] != localStatus[seq] - '0') {
            return false;
        }
    }
    return true;
}

__attribute__((no_sanitize("cfi"))) void SmartReminderCenter::GetReminderAffecteds(
    const map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice,
    const sptr<NotificationRequest> &request,
    vector<shared_ptr<ReminderAffected>> &reminderAffecteds) const
{
    string strSlotType = to_string(static_cast<int32_t>(request->GetSlotType()));
    string contentTypeCombination = strSlotType;
    contentTypeCombination.append("#");
    if (request->GetContent() != nullptr) {
        contentTypeCombination.append(to_string(static_cast<int32_t>(request->GetContent()->GetContentType())));
    }
    string typeCodeCombination = contentTypeCombination;
    typeCodeCombination.append("#");
    if (request->GetContent() != nullptr && request->GetContent()->GetNotificationContent() != nullptr) {
        NotificationLocalLiveViewContent *localLiveView =
            static_cast<NotificationLocalLiveViewContent *>(&(*(request->GetContent()->GetNotificationContent())));
        typeCodeCombination.append(to_string(localLiveView->GetType()));
    }
    auto iter = reminderFilterDevice.find(typeCodeCombination);
    if (iter != reminderFilterDevice.end()) {
        reminderAffecteds = iter->second;
        return;
    }
    iter = reminderFilterDevice.find(contentTypeCombination);
    if (iter != reminderFilterDevice.end()) {
        reminderAffecteds = iter->second;
        return;
    }
    iter = reminderFilterDevice.find(strSlotType);
    if (iter != reminderFilterDevice.end()) {
        reminderAffecteds = iter->second;
        return;
    }
    ANS_LOGD("GetReminderAffecteds fail as wrong notification_config.json possibly. TypeCombination = %{public}s.",
        typeCodeCombination.c_str());
}

void SmartReminderCenter::GetDeviceStatusByType(
    const string &deviceType, bitset<DistributedDeviceStatus::STATUS_SIZE> &bitStatus) const
{
    u_int32_t status = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(deviceType);
    bitStatus = bitset<DistributedDeviceStatus::STATUS_SIZE>(status);
    if (deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) == 0) {
        bool screenLocked = true;
        screenLocked = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
        bitStatus.set(DistributedDeviceStatus::LOCK_FLAG, !screenLocked);
    }
    ANS_LOGD("GetDeviceStatusByType deviceType: %{public}s, bitStatus: %{public}s.",
        deviceType.c_str(), bitStatus.to_string().c_str());
}
}  // namespace Notification
}  // namespace OHOS