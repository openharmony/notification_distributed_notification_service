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
#include "distributed_service.h"

#include "notification_helper.h"
#include "distributed_client.h"
#include "state_box.h"
#include "in_process_call_wrapper.h"
#include "distributed_observer_service.h"
#include "distributed_device_data.h"
#include "dm_device_info.h"
#include "match_box.h"
#include "bundle_icon_box.h"
#include "distributed_preference.h"
#include "bundle_resource_helper.h"
#include "notification_sync_box.h"

namespace OHOS {
namespace Notification {

std::string TransDeviceTypeIdToName(uint16_t deviceType)
{
    switch (deviceType) {
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH: {
            return "wearable";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD: {
            return "Pad";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE: {
            return "Phone";
        }
        default:
            return "";
    }
}

namespace {
constexpr uint32_t DEFAULT_LOCK_SCREEN_FLAG = 2;
}

void DistributedService::InitDeviceState(const DistributedDeviceInfo device)
{
    if (device.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE &&
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        int32_t state = OberverService::GetInstance().IsScreenLocked();
        SyncDeviceState(state);
    }
}

void DistributedService::HandleDeviceState(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t state;
    std::string deviceName;
    NotifticationStateBox stateBox = NotifticationStateBox(boxMessage);
    if (!stateBox.GetDeviceType(deviceName) || !stateBox.GetState(state)) {
        ANS_LOGW("Dans unbox state failed.");
        return;
    }
    std::string deviceId;
    if (!stateBox.GetDeviceId(deviceId)) {
        ANS_LOGW("Dans unbox deviceId failed.");
    }
    uint32_t status = (static_cast<uint32_t>(state) << 1);
    int32_t result = NotificationHelper::SetTargetDeviceStatus(deviceName, status,
        DEFAULT_LOCK_SCREEN_FLAG, deviceId);
    ANS_LOGI("Dans set state %{public}s %{public}d.", deviceName.c_str(), state);
}

void DistributedService::SyncDeviceState(int32_t state)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, state]() {
        std::shared_ptr<NotifticationStateBox> stateBox = std::make_shared<NotifticationStateBox>();
        stateBox->SetState(state);
        stateBox->SetDeviceType(TransDeviceTypeIdToName(localDevice_.deviceType_));
        stateBox->SetDeviceId(localDevice_.deviceId_);
        if (!stateBox->Serialize()) {
            ANS_LOGW("Dans SyncDeviceState serialize failed.");
            return;
        }
        for (const auto& peer : peerDevice_) {
            DistributedClient::GetInstance().SendMessage(stateBox, TransDataType::DATA_TYPE_MESSAGE,
                peer.second.deviceId_, peer.second.deviceType_);
            ANS_LOGI("Dans SyncDeviceState %{public}d %{public}d %{public}d %{public}d.",
                peer.second.deviceType_, localDevice_.deviceType_, state, (int32_t)(peerDevice_.size()));
        }
    });
    serviceQueue_->submit(task);
}

int32_t DistributedService::SyncDeviceMatch(const DistributedDeviceInfo peerDevice, MatchType type)
{
    std::shared_ptr<NotifticationMatchBox> matchBox = std::make_shared<NotifticationMatchBox>();
    matchBox->SetVersion(CURRENT_VERSION);
    matchBox->SetMatchType(type);
    matchBox->SetLocalDeviceId(localDevice_.deviceId_);
    matchBox->SetLocalDeviceType(localDevice_.deviceType_);
    if (type == MatchType::MATCH_ACK) {
        matchBox->SetPeerDeviceId(peerDevice.deviceId_);
        matchBox->SetPeerDeviceType(peerDevice.deviceType_);
    }
    if (!matchBox->Serialize()) {
        ANS_LOGW("Dans SyncDeviceMatch serialize failed.");
        return -1;
    }
    int32_t result = DistributedClient::GetInstance().SendMessage(matchBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, peerDevice.deviceType_);
    ANS_LOGI("Dans SyncDeviceMatch %{public}s %{public}d %{public}s %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), localDevice_.deviceType_, type);
    return result;
}

void DistributedService::SyncAllLiveViewNotification(const DistributedDeviceInfo peerDevice, bool isForce)
{
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }

    auto iter = peerDevice_.find(peerDevice.deviceId_);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans %{public}s.", StringAnonymous(peerDevice.deviceId_).c_str());
        return;
    }

    if (!isForce && iter->second.isSync) {
        ANS_LOGI("Dans %{public}d %{public}d.", isForce, iter->second.isSync);
        return;
    }

    std::vector<sptr<Notification>> notifications;
    auto result = NotificationHelper::GetAllNotificationsBySlotType(notifications,
        NotificationConstant::SlotType::LIVE_VIEW);
    if (result != ERR_OK) {
        ANS_LOGI("Dans get all active %{public}d.", result);
        return;
    }

    std::vector<std::string> notificationList;
    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            ANS_LOGI("Dans no need sync remove notification.");
            continue;
        }
        notificationList.push_back(notification->GetKey());
    }
    SyncNotifictionList(peerDevice, notificationList);

    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            ANS_LOGI("Dans no need sync notification.");
            continue;
        }
        std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
        SendNotifictionRequest(sharedNotification, peerDevice, true);
    }
}

void DistributedService::SyncNotifictionList(const DistributedDeviceInfo& peerDevice,
    const std::vector<std::string>& notificationList)
{
    ANS_LOGI("Dans sync notification %{public}d.", (int32_t)(notificationList.size()));
    std::shared_ptr<NotificationSyncBox> notificationSyncBox = std::make_shared<NotificationSyncBox>();
    notificationSyncBox->SetLocalDeviceId(peerDevice.deviceId_);
    notificationSyncBox->SetNotificationEmpty(notificationList.empty());
    if (!notificationList.empty()) {
        notificationSyncBox->SetNotificationList(notificationList);
    }

    if (!notificationSyncBox->Serialize()) {
        ANS_LOGW("Dans SyncNotifictionList serialize failed.");
        return;
    }
    int32_t result = DistributedClient::GetInstance().SendMessage(notificationSyncBox,
        TransDataType::DATA_TYPE_BYTES, peerDevice.deviceId_, peerDevice.deviceType_);
    ANS_LOGI("Dans SyncNotifictionList %{public}s %{public}d %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), localDevice_.deviceType_);
}

void DistributedService::HandleMatchSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t type = 0;
    DistributedDeviceInfo peerDevice;
    NotifticationMatchBox matchBox = NotifticationMatchBox(boxMessage);
    if (!matchBox.GetLocalDeviceType(type)) {
        ANS_LOGI("Dans handle match device type failed.");
        return;
    } else {
        peerDevice.deviceType_ = static_cast<uint16_t>(type);
    }
    if (!matchBox.GetLocalDeviceId(peerDevice.deviceId_)) {
        ANS_LOGI("Dans handle match device id failed.");
        return;
    }
    int32_t matchType = 0;
    if (!matchBox.GetMatchType(matchType)) {
        ANS_LOGI("Dans handle match sync failed.");
        return;
    }
    ANS_LOGI("Dans handle match device type %{public}d.", matchType);
    if (matchType == MatchType::MATCH_SYN) {
        SyncDeviceMatch(peerDevice, MatchType::MATCH_ACK);
        RequestBundlesIcon(peerDevice, true);
        SyncAllLiveViewNotification(peerDevice, true);
    } else if (matchType == MatchType::MATCH_ACK) {
        InitDeviceState(peerDevice);
        RequestBundlesIcon(peerDevice, false);
        SubscribeNotifictaion(peerDevice);
        SyncAllLiveViewNotification(peerDevice, false);
    }

    auto iter = peerDevice_.find(peerDevice.deviceId_);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans get deviceId unknonw %{public}s.", peerDevice.deviceId_.c_str());
        return;
    }
    iter->second.isSync = true;
}

bool DistributedService::CheckPeerDevice(const BundleIconBox& boxMessage, DistributedDeviceInfo& device)
{
    std::string deviceId;
    if (!boxMessage.GetLocalDeviceId(deviceId)) {
        ANS_LOGI("Dans get deviceId failed.");
        return false;
    }
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans get deviceId unknonw %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    device = iter->second;
    return true;
}

void DistributedService::ReportBundleIconList(const DistributedDeviceInfo peerDevice)
{
    if (localDevice_.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }
    std::vector<std::string> bundlesName;
    DistributedPreferences::GetInstance().GetSavedBundlesIcon(bundlesName);
    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    iconBox->SetIconSyncType(IconSyncType::REPORT_SAVED_ICON);
    iconBox->SetBundleList(bundlesName);
    iconBox->SetLocalDeviceId(localDevice_.deviceId_);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans ReportBundleIconList serialize failed.");
        return;
    }

    DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, peerDevice.deviceType_);
    ANS_LOGI("Dans ReportBundleIconList %{public}s %{public}d %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), localDevice_.deviceType_);
}

void DistributedService::RequestBundlesIcon(const DistributedDeviceInfo peerDevice, bool isForce)
{
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }

    auto iter = peerDevice_.find(peerDevice.deviceId_);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans %{public}s.", StringAnonymous(peerDevice.deviceId_).c_str());
        return;
    }

    if (!isForce && iter->second.isSync) {
        ANS_LOGI("Dans %{public}d %{public}d.", isForce, iter->second.isSync);
        return;
    }

    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    iconBox->SetIconSyncType(IconSyncType::REQUEST_BUNDLE_ICON);
    iconBox->SetLocalDeviceId(localDevice_.deviceId_);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans RequestBundlesIcon serialize failed.");
        return;
    }

    DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, peerDevice.deviceType_);
    ANS_LOGI("Dans RequestBundlesIcon %{public}s %{public}d %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), localDevice_.deviceType_);
}

int32_t DistributedService::UpdateBundlesIcon(const std::unordered_map<std::string, std::string>& icons,
    const DistributedDeviceInfo peerDevice)
{
    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    iconBox->SetIconSyncType(IconSyncType::UPDATE_BUNDLE_ICON);
    iconBox->SetBundlesIcon(icons);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans UpdateBundlesIcon serialize failed.");
        return -1;
    }

    int32_t result = DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_BYTES,
        peerDevice.deviceId_, peerDevice.deviceType_);
    ANS_LOGI("Dans UpdateBundlesIcon %{public}s %{public}d %{public}s %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), localDevice_.deviceType_, result);
    return result;
}

void DistributedService::GenerateBundleIconSync(const DistributedDeviceInfo& device)
{
    std::vector<NotificationBundleOption> bundleOption;
    if (NotificationHelper::GetAllLiveViewEnabledBundles(bundleOption) != 0) {
        ANS_LOGW("Dans get all live view enable bundle failed.");
        return;
    }

    std::vector<NotificationBundleOption> enableBundleOption;
    if (NotificationHelper::GetAllDistribuedEnabledBundles("liteWearable", enableBundleOption) != 0) {
        ANS_LOGW("Dans get all live view enable bundle failed.");
    }

    std::set<std::string> enabledBundles;
    for (auto item : enableBundleOption) {
        enabledBundles.insert(item.GetBundleName());
    }
    std::set<std::string> cachedIcons;
    std::vector<std::string> unCachedBundleList;
    if (bundleIconCache_.find(device.deviceId_) != bundleIconCache_.end()) {
        cachedIcons = bundleIconCache_[device.deviceId_];
    }
    for (auto item : bundleOption) {
        if (enabledBundles.find(item.GetBundleName()) != enabledBundles.end() ||
            cachedIcons.find(item.GetBundleName()) != cachedIcons.end()) {
            continue;
        }
        unCachedBundleList.push_back(item.GetBundleName());
    }

    ANS_LOGI("Dans Generate bundle %{public}d %{public}d %{public}d.", (int32_t)(bundleOption.size()),
        (int32_t)(enableBundleOption.size()), (int32_t)(unCachedBundleList.size()));
    std::vector<std::string> sendIcon;
    std::unordered_map<std::string, std::string> icons;
    for (auto bundle : unCachedBundleList) {
        std::string icon;
        if (!GetBundleResourceInfo(bundle, icon)) {
            continue;
        }
        sendIcon.push_back(bundle);
        icons.insert(std::make_pair(bundle, icon));
        if (icons.size() == BundleIconBox::MAX_ICON_NUM) {
            if (UpdateBundlesIcon(icons, device) == ERR_OK) {
                cachedIcons.insert(sendIcon.begin(), sendIcon.end());
            }
            icons.clear();
            sendIcon.clear();
        }
    }
    if (!icons.empty() && UpdateBundlesIcon(icons, device) == ERR_OK) {
        cachedIcons.insert(sendIcon.begin(), sendIcon.end());
    }
    bundleIconCache_[device.deviceId_] = cachedIcons;
}

void DistributedService::HandleBundleIconSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t type = 0;
    BundleIconBox iconBox = BundleIconBox(boxMessage);
    if (!iconBox.GetIconSyncType(type)) {
        ANS_LOGI("Dans handle bundle icon sync failed.");
        return;
    }

    ANS_LOGI("Dans handle bundl icon type %{public}d %{public}d.", type, localDevice_.deviceType_);
    if (type == IconSyncType::REPORT_SAVED_ICON &&
        localDevice_.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        DistributedDeviceInfo device;
        if (!CheckPeerDevice(iconBox, device)) {
            return;
        }
        std::set<std::string> bundleSet;
        std::vector<std::string> bundleList;
        iconBox.GetBundleList(bundleList);
        for (auto bundle : bundleList) {
            ANS_LOGI("Dans handle receive %{public}s.", bundle.c_str());
            bundleSet.insert(bundle);
        }
        bundleIconCache_[device.deviceId_] = bundleSet;
        GenerateBundleIconSync(device);
    }

    if (type == IconSyncType::UPDATE_BUNDLE_ICON &&
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        std::unordered_map<std::string, std::string> bundlesIcon;
        if (!iconBox.GetBundlesIcon(bundlesIcon)) {
            ANS_LOGI("Dans handle bundle icon get icon failed.");
            return;
        }
        DistributedPreferences::GetInstance().InertBatchBundleIcons(bundlesIcon);
    }

    if (type == IconSyncType::REQUEST_BUNDLE_ICON &&
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        DistributedDeviceInfo device;
        if (!CheckPeerDevice(iconBox, device)) {
            return;
        }
        ReportBundleIconList(device);
    }

    if (type == IconSyncType::REMOVE_BUNDLE_ICON &&
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        std::vector<std::string> bundleList;
        iconBox.GetBundleList(bundleList);
        for (auto& bundle : bundleList) {
            DistributedPreferences::GetInstance().DeleteBundleIcon(bundle);
        }
    }
}
}
}
