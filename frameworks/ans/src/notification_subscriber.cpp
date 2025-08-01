/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "notification_subscriber.h"

#include "ans_trace_wrapper.h"
#include "notification_constant.h"
#include "hitrace_meter_adapter.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
NotificationSubscriber::NotificationSubscriber()
{
    impl_ = new (std::nothrow) SubscriberImpl(*this);
    deviceType_ = NotificationConstant::CURRENT_DEVICE_TYPE;
};

NotificationSubscriber::~NotificationSubscriber()
{}

void NotificationSubscriber::SetDeviceType(const std::string &deviceType)
{
    deviceType_ = deviceType;
}

std::string NotificationSubscriber::GetDeviceType() const
{
    return deviceType_;
}

bool NotificationSubscriber::SyncLiveViewVoip(
    const std::string &deviceType, std::shared_ptr<Notification> &notification) const
{
    sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("No need to consume cause invalid reqeuest.");
        return false;
    }
    if (request->GetClassification() == NotificationConstant::ANS_VOIP &&
        request->GetSlotType() == NotificationConstant::LIVE_VIEW &&
        (deviceType == CURRENT_DEVICE_TYPE || deviceType == NotificationConstant::LITEWEARABLE_DEVICE_TYPE ||
        deviceType == NotificationConstant::HEADSET_DEVICE_TYPE || deviceType ==
        NotificationConstant::WEARABLE_DEVICE_TYPE)) {
        return true;
    }
    return false;
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
bool NotificationSubscriber::ProcessSyncDecision(
    const std::string &deviceType, std::shared_ptr<Notification> &notification) const
{
    sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("null request");
        return false;
    }

    auto flagsMap = request->GetDeviceFlags();
    if (flagsMap == nullptr || flagsMap->size() <= 0) {
        return true;
    }
    auto flagIter = flagsMap->find(deviceType);
    if (flagIter != flagsMap->end() && flagIter->second != nullptr) {
        request->SetFlags(flagIter->second);
        ANS_LOGI("SetFlags-final, notificationKey = %{public}s flags = %{public}d",
            request->GetKey().c_str(), request->GetFlags()->GetReminderFlags());
        return true;
    }
    if (deviceType.size() <= 0 || deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) == 0) {
        return true;
    }
    ANS_LOGE("Cannot find deviceFlags,notificationKey = %{public}s, deviceType: %{public}s.",
        request->GetKey().c_str(), deviceType.c_str());
    return false;
}

NotificationConstant::FlagStatus NotificationSubscriber::DowngradeReminder(
    const NotificationConstant::FlagStatus &oldFlags, const NotificationConstant::FlagStatus &judgeFlags) const
{
    if (judgeFlags == NotificationConstant::FlagStatus::NONE || oldFlags == NotificationConstant::FlagStatus::NONE) {
        return NotificationConstant::FlagStatus::NONE;
    }
    if (judgeFlags > oldFlags) {
        return judgeFlags;
    } else {
        return oldFlags;
    }
}
#endif

const sptr<NotificationSubscriber::SubscriberImpl> NotificationSubscriber::GetImpl() const
{
    return impl_;
}

NotificationSubscriber::SubscriberImpl::SubscriberImpl(NotificationSubscriber &subscriber) : subscriber_(subscriber)
{
    recipient_ = new (std::nothrow) DeathRecipient(*this);
};

ErrCode NotificationSubscriber::SubscriberImpl::OnConnected()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (proxy != nullptr) {
        proxy->AsObject()->AddDeathRecipient(recipient_);
        ANS_LOGD("%s, Add death recipient.", __func__);
    }
    subscriber_.OnConnected();
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnDisconnected()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (proxy != nullptr) {
        proxy->AsObject()->RemoveDeathRecipient(recipient_);
        ANS_LOGD("%s, Remove death recipient.", __func__);
    }
    subscriber_.OnDisconnected();
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnConsumed(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationMap == nullptr) {
        ANS_LOGE("null notificationMap");
        return ERR_INVALID_DATA;
    }
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    auto deviceType = subscriber_.GetDeviceType();
    if (subscriber_.SyncLiveViewVoip(deviceType, sharedNotification)) {
        ANS_LOGI("Sync LIVE_VIEW VOIP.");
    }
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    else if (!subscriber_.ProcessSyncDecision(deviceType, sharedNotification)) {
        return ERR_OK;
    }
#endif
    subscriber_.OnConsumed(
        sharedNotification, std::make_shared<NotificationSortingMap>(*notificationMap));
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnConsumed(const sptr<Notification> &notification)
{
    return OnConsumed(notification, nullptr);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnConsumedWithMaxCapacity(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    return OnConsumed(notification, notificationMap);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnConsumedWithMaxCapacity(const sptr<Notification> &notification)
{
    return OnConsumed(notification, nullptr);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnConsumedList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    for (auto notification : notifications) {
        OnConsumed(notification, notificationMap);
    }
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnConsumedList(const std::vector<sptr<Notification>> &notifications)
{
    return OnConsumedList(notifications, nullptr);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationMap == nullptr) {
        subscriber_.OnCanceled(std::make_shared<Notification>(*notification),
            std::make_shared<NotificationSortingMap>(), deleteReason);
    } else {
        subscriber_.OnCanceled(std::make_shared<Notification>(*notification),
            std::make_shared<NotificationSortingMap>(*notificationMap), deleteReason);
    }
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnCanceled(
    const sptr<Notification> &notification, int32_t deleteReason)
{
    return OnCanceled(notification, nullptr, deleteReason);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnCanceledWithMaxCapacity(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    return OnCanceled(notification, notificationMap, deleteReason);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnCanceledWithMaxCapacity(
    const sptr<Notification> &notification, int32_t deleteReason)
{
    return OnCanceled(notification, nullptr, deleteReason);
}

void NotificationSubscriber::SubscriberImpl::OnBatchCanceled(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    std::vector<std::shared_ptr<Notification>> notificationList;
    for (auto notification : notifications) {
        notificationList.emplace_back(std::make_shared<Notification>(*notification));
    }
    if (notificationMap == nullptr) {
        subscriber_.OnBatchCanceled(notificationList,
            std::make_shared<NotificationSortingMap>(), deleteReason);
    } else {
        subscriber_.OnBatchCanceled(notificationList,
            std::make_shared<NotificationSortingMap>(*notificationMap), deleteReason);
    }
}


ErrCode NotificationSubscriber::SubscriberImpl::OnCanceledList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber_.HasOnBatchCancelCallback()) {
        OnBatchCanceled(notifications, notificationMap, deleteReason);
        return ERR_OK;
    }
    for (auto notification : notifications) {
        OnCanceled(notification, notificationMap, deleteReason);
    }
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnCanceledList(
    const std::vector<sptr<Notification>> &notifications, int32_t deleteReason)
{
    return OnCanceledList(notifications, nullptr, deleteReason);
}

ErrCode NotificationSubscriber::SubscriberImpl::OnUpdated(const sptr<NotificationSortingMap> &notificationMap)
{
    subscriber_.OnUpdate(std::make_shared<NotificationSortingMap>(*notificationMap));
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date)
{
    subscriber_.OnDoNotDisturbDateChange(std::make_shared<NotificationDoNotDisturbDate>(*date));
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnEnabledNotificationChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    subscriber_.OnEnabledNotificationChanged(std::make_shared<EnabledNotificationCallbackData>(*callbackData));
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    subscriber_.OnBadgeChanged(std::make_shared<BadgeNumberCallbackData>(*badgeData));
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnBadgeEnabledChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    subscriber_.OnBadgeEnabledChanged(callbackData);
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnApplicationInfoNeedChanged(
    const std::string& bundleName)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    subscriber_.OnApplicationInfoNeedChanged(bundleName);
    return ERR_OK;
}

ErrCode NotificationSubscriber::SubscriberImpl::OnOperationResponse(
    const sptr<NotificationOperationInfo> &operationInfo, int32_t& funcResult)
{
    return subscriber_.OnOperationResponse(std::make_shared<NotificationOperationInfo>(*operationInfo));
}

sptr<IAnsManager> NotificationSubscriber::SubscriberImpl::GetAnsManagerProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (!remoteObject) {
        return nullptr;
    }

    sptr<IAnsManager> proxy = iface_cast<IAnsManager>(remoteObject);
    if ((proxy == nullptr) || (proxy->AsObject() == nullptr)) {
        return nullptr;
    }

    return proxy;
}

NotificationSubscriber::SubscriberImpl::DeathRecipient::DeathRecipient(SubscriberImpl &subscriberImpl)
    : subscriberImpl_(subscriberImpl) {};

NotificationSubscriber::SubscriberImpl::DeathRecipient::~DeathRecipient() {};

void NotificationSubscriber::SubscriberImpl::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    subscriberImpl_.subscriber_.OnDied();
}
}  // namespace Notification
}  // namespace OHOS
