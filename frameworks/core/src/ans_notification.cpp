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

#include "ans_notification.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_manager_death_recipient.h"
#include "ans_manager_proxy.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "notification_button_option.h"
#include "notification_local_live_view_subscriber.h"
#include "system_ability_definition.h"
#include "unique_fd.h"
#include "hitrace_util.h"

#include <memory>
#include <thread>

namespace OHOS {
namespace Notification {
namespace {
const int32_t MAX_RETRY_TIME = 30;
const int32_t SLEEP_TIME = 1000;
const uint32_t MAX_PUBLISH_DELAY_TIME = 5;
const std::string DOWNLOAD_TITLE = "title";
const std::string DOWNLOAD_FILENAME = "fileName";
const static int MAX_SLOT_FLAGS = 0b111111;
}
ErrCode AnsNotification::AddNotificationSlot(const NotificationSlot &slot)
{
    std::vector<NotificationSlot> slots;
    slots.push_back(slot);
    return AddNotificationSlots(slots);
}

ErrCode AnsNotification::AddSlotByType(const NotificationConstant::SlotType &slotType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddSlotByType(slotType);
}

ErrCode AnsNotification::AddNotificationSlots(const std::vector<NotificationSlot> &slots)
{
    if (slots.size() == 0) {
        ANS_LOGE("Failed to add notification slots because input slots size is 0.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationSlot>> slotsSptr;
    for (auto it = slots.begin(); it != slots.end(); ++it) {
        sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(*it);
        if (slot == nullptr) {
            ANS_LOGE("null slot");
            return ERR_ANS_NO_MEMORY;
        }
        slotsSptr.emplace_back(slot);
    }

    size_t slotsSize = slotsSptr.size();
    if (slotsSize > MAX_SLOT_NUM) {
        ANS_LOGE("slotsSize over max size");
        return ERR_ANS_INVALID_PARAM;
    }

    return proxy->AddSlots(slotsSptr);
}

ErrCode AnsNotification::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGI("slotType:%{public}d", slotType);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveSlotByType(slotType);
}

ErrCode AnsNotification::RemoveAllSlots()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveAllSlots();
}

ErrCode AnsNotification::GetNotificationSlot(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetSlotByType(slotType, slot);
}

ErrCode AnsNotification::GetNotificationSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetSlots(slots);
}

ErrCode AnsNotification::GetNotificationSlotNumAsBundle(const NotificationBundleOption &bundleOption, uint64_t &num)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetSlotNumAsBundle(bo, num);
}

ErrCode AnsNotification::GetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t &slotFlags)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetSlotFlagsAsBundle(bo, slotFlags);
}

ErrCode AnsNotification::GetNotificationSettings(uint32_t &slotFlags)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetNotificationSettings(slotFlags);
}

ErrCode AnsNotification::SetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t slotFlags)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGI("bundleName:%{public}s, %{public}d", bundleOption.GetBundleName().c_str(), (int)slotFlags);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));

    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (slotFlags > MAX_SLOT_FLAGS) {
        ANS_LOGE("Invalid slotFlags");
        return ERR_ANS_INVALID_PARAM;
    }
    // got the LSB 6 bits as slotflags;
    uint32_t validSlotFlag = MAX_SLOT_FLAGS & slotFlags;

    return proxy->SetSlotFlagsAsBundle(bo, validSlotFlag);
}

ErrCode AnsNotification::PublishNotification(const NotificationRequest &request, const std::string &instanceKey)
{
    ANS_LOGD("called");
    return PublishNotification(std::string(), request, instanceKey);
}

ErrCode AnsNotification::PublishNotification(const std::string &label, const NotificationRequest &request,
    const std::string &instanceKey)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGI("notificationId:%{public}u", request.GetNotificationId());

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!IsValidTemplate(request) || !IsValidDelayTime(request)) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the series numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_NO_MEMORY;
    }
    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    reqPtr->SetAppInstanceKey(instanceKey);
    if (reqPtr->IsCommonLiveView()) {
        return proxy->PublishWithMaxCapacity(label, reqPtr);
    }
    return proxy->Publish(label, reqPtr);
}

ErrCode AnsNotification::PublishNotificationForIndirectProxy(const NotificationRequest &request)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    TraceChainUtil traceChain = TraceChainUtil();
    ANS_LOGI("notificationId:%{public}u", request.GetNotificationId());

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!IsValidTemplate(request) || !IsValidDelayTime(request)) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the series numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_NO_MEMORY;
    }
    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    if (reqPtr->IsCommonLiveView()) {
        return proxy->PublishNotificationForIndirectProxyWithMaxCapacity(reqPtr);
    }
    return proxy->PublishNotificationForIndirectProxy(reqPtr);
}

ErrCode AnsNotification::CancelNotification(int32_t notificationId, const std::string &instanceKey)
{
    return CancelNotification("", notificationId, instanceKey);
}

ErrCode AnsNotification::CancelNotification(const std::string &label, int32_t notificationId,
    const std::string &instanceKey)
{
    ANS_LOGI("notificationId:%{public}d", notificationId);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->Cancel(notificationId, label, instanceKey);
}

ErrCode AnsNotification::CancelAllNotifications(const std::string &instanceKey)
{
    ANS_LOGI("called");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelAll(instanceKey);
}

ErrCode AnsNotification::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGI("notificationId:%{public}d", notificationId);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelAsBundle(notificationId, representativeBundle, userId);
}

ErrCode AnsNotification::CancelAsBundle(
    const NotificationBundleOption &bundleOption, int32_t notificationId)
{
    ANS_LOGI("notificationId:%{public}d", notificationId);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->CancelAsBundle(bo, notificationId);
}

ErrCode AnsNotification::GetActiveNotificationNums(uint64_t &num)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetActiveNotificationNums(num);
}

ErrCode AnsNotification::GetActiveNotifications(std::vector<sptr<NotificationRequest>> &request,
    const std::string &instanceKey)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetActiveNotifications(request, instanceKey);
}

ErrCode AnsNotification::CanPublishNotificationAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    if (representativeBundle.empty()) {
        ANS_LOGW("Input representativeBundle is empty");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CanPublishAsBundle(representativeBundle, canPublish);
}

ErrCode AnsNotification::PublishNotificationAsBundle(
    const std::string &representativeBundle, const NotificationRequest &request)
{
    ANS_LOGI("Bundle:%{public}s, notificationId:%{public}u",
        representativeBundle.c_str(), request.GetNotificationId());
    if (representativeBundle.empty()) {
        ANS_LOGE("Refuse to publish the notification whit invalid representativeBundle");
        return ERR_ANS_INVALID_PARAM;
    }

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without effective content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the sequence numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture overtake the limit");
        return checkErr;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_NO_MEMORY;
    }
    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    if (reqPtr->IsCommonLiveView()) {
        return proxy->PublishAsBundleWithMaxCapacity(reqPtr, representativeBundle);
    }
    return proxy->PublishAsBundle(reqPtr, representativeBundle);
}

ErrCode AnsNotification::SetNotificationBadgeNum()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t num = -1;
    return proxy->SetNotificationBadgeNum(num);
}

ErrCode AnsNotification::SetNotificationBadgeNum(int32_t num)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationBadgeNum(num);
}

ErrCode AnsNotification::IsAllowedNotify(bool &allowed)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->IsAllowedNotify(allowed);
}

ErrCode AnsNotification::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->IsAllowedNotifySelf(allowed);
}

ErrCode AnsNotification::CanPopEnableNotificationDialog(sptr<AnsDialogHostClient> &hostClient,
    bool &canPop, std::string &bundleName)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CanPopEnableNotificationDialog(hostClient, canPop, bundleName);
}

ErrCode AnsNotification::RemoveEnableNotificationDialog()
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveEnableNotificationDialog();
}

ErrCode AnsNotification::RequestEnableNotification(std::string &deviceId,
    sptr<AnsDialogHostClient> &hostClient,
    sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    if (hostClient == nullptr) {
        ANS_LOGE("null hostClient");
        return ERR_ANS_INVALID_PARAM;
    }
    if (callerToken == nullptr) {
        return proxy->RequestEnableNotification(deviceId, hostClient);
    }
    return proxy->RequestEnableNotification(deviceId, hostClient, callerToken);
}

ErrCode AnsNotification::RequestEnableNotification(const std::string bundleName, const int32_t uid)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RequestEnableNotification(bundleName, uid);
}

ErrCode AnsNotification::HasNotificationPolicyAccessPermission(bool &hasPermission)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->HasNotificationPolicyAccessPermission(hasPermission);
}

ErrCode AnsNotification::GetBundleImportance(NotificationSlot::NotificationLevel &importance)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t importanceTemp;
    ErrCode ret = proxy->GetBundleImportance(importanceTemp);
    if ((NotificationSlot::LEVEL_NONE <= importanceTemp) && (importanceTemp <= NotificationSlot::LEVEL_HIGH)) {
        importance = static_cast<NotificationSlot::NotificationLevel>(importanceTemp);
    } else {
        importance = NotificationSlot::LEVEL_UNDEFINED;
    }
    return ret;
}

ErrCode AnsNotification::SubscribeNotification(const NotificationSubscriber &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->Subscribe(subscriberSptr);
}

ErrCode AnsNotification::SubscribeNotificationSelf(const NotificationSubscriber &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SubscribeSelf(subscriberSptr);
}

ErrCode AnsNotification::SubscribeLocalLiveViewNotification(const NotificationLocalLiveViewSubscriber &subscriber,
    const bool isNative)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SubscribeLocalLiveView(subscriberSptr, isNative);
}

ErrCode AnsNotification::SubscribeNotification(
    const NotificationSubscriber &subscriber, const NotificationSubscribeInfo &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo(subscribeInfo);
    if (sptrInfo == nullptr) {
        ANS_LOGE("null sptrInfo");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INVALID_PARAM;
    }
    if (!subscribeInfo.GetDeviceType().empty()) {
        subscriberSptr->subscriber_.SetDeviceType(subscribeInfo.GetDeviceType());
    }
    return proxy->Subscribe(subscriberSptr, sptrInfo);
}

ErrCode AnsNotification::UnSubscribeNotification(NotificationSubscriber &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->Unsubscribe(subscriberSptr);
}

ErrCode AnsNotification::UnSubscribeNotification(
    NotificationSubscriber &subscriber, NotificationSubscribeInfo subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo(subscribeInfo);
    if (sptrInfo == nullptr) {
        ANS_LOGE("null sptrInfo");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->Unsubscribe(subscriberSptr, sptrInfo);
}

ErrCode AnsNotification::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    return SubscribeNotification(subscriber, nullptr);
}

ErrCode AnsNotification::SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("null listener");
        return ERR_ANS_NO_MEMORY;
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();
    return proxy->SubscribeSelf(listener);
}

ErrCode AnsNotification::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("null listener");
        return ERR_ANS_NO_MEMORY;
    }
    if (subscribeInfo != nullptr && !subscribeInfo->GetDeviceType().empty()) {
        subscriber->SetDeviceType(subscribeInfo->GetDeviceType());
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();

    if (subscribeInfo == nullptr) {
        return proxy->Subscribe(listener);
    }
    return proxy->Subscribe(listener, subscribeInfo);
}

ErrCode AnsNotification::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    return UnSubscribeNotification(subscriber, nullptr);
}

ErrCode AnsNotification::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    auto item = subscribers_.find(subscriber);
    if (item != subscribers_.end()) {
        sptr<SubscriberListener> listener = item->second;
        int32_t ret = -1;
        if (subscribeInfo == nullptr) {
            ret = proxy->Unsubscribe(listener);
        } else {
            ret = proxy->Unsubscribe(listener, subscribeInfo);
        }
        if (ret == ERR_OK) {
            subscribers_.erase(item);
        }
        return ret;
    }
    ANS_LOGE("Failed to unsubscribe due to subscriber not found.");
    return ERR_ANS_INVALID_PARAM;
}

ErrCode AnsNotification::TriggerLocalLiveView(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const NotificationButtonOption &buttonOption)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    if (buttonOption.GetButtonName().empty()) {
        ANS_LOGE("Invalid button name.");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGI("notificationId:%{public}u,bundleName:%{public}s,button:%{public}s",
        notificationId, bundleOption.GetBundleName().c_str(), buttonOption.GetButtonName().c_str());

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    sptr<NotificationButtonOption> button(new (std::nothrow) NotificationButtonOption(buttonOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->TriggerLocalLiveView(bo, notificationId, button);
}

ErrCode AnsNotification::RemoveNotification(const std::string &key, int32_t removeReason)
{
    ANS_LOGI("key:%{public}s,removeReason:%{public}d", key.c_str(), removeReason);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (key.empty()) {
        ANS_LOGW("Input key is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->Delete(key, removeReason);
}

ErrCode AnsNotification::RemoveNotification(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const std::string &label, int32_t removeReason)
{
    ANS_LOGI("notificationId:%{public}d,bundle:%{public}s,reason:%{public}d label:%{public}s",
        notificationId, bundleOption.GetBundleName().c_str(), removeReason, label.c_str());
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->RemoveNotification(bo, notificationId, label, removeReason);
}

ErrCode AnsNotification::RemoveAllNotifications(const NotificationBundleOption &bundleOption)
{
    ANS_LOGI("bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy defeat.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->RemoveAllNotifications(bo);
}

ErrCode AnsNotification::RemoveNotifications(const std::vector<std::string> hashcodes, int32_t removeReason)
{
    ANS_LOGI("removeReason:%{public}d", removeReason);
    if (hashcodes.empty()) {
        ANS_LOGE("Hashcodes is empty");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->RemoveNotifications(hashcodes, removeReason);
}

ErrCode AnsNotification::RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
    const NotificationConstant::SlotType& slotType,
    const NotificationConstant::DistributedDeleteType& deleteType,
    const int32_t removeReason, const std::string& deviceId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->RemoveDistributedNotifications(hashcodes, slotType, deleteType,
        removeReason, deviceId);
}

ErrCode AnsNotification::RemoveNotificationsByBundle(const NotificationBundleOption &bundleOption)
{
    ANS_LOGI("bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Defeated to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->DeleteByBundle(bo);
}

ErrCode AnsNotification::RemoveNotifications()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->DeleteAll();
}

ErrCode AnsNotification::GetNotificationSlotsForBundle(
    const NotificationBundleOption &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundleName is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetSlotsByBundle(bo, slots);
}

ErrCode AnsNotification::GetNotificationSlotForBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundleName is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetSlotByBundle(bo, slotType, slot);
}

ErrCode AnsNotification::UpdateNotificationSlots(
    const NotificationBundleOption &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy flop.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));

    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (slots.empty()) {
        ANS_LOGE("empty slots");
        return ERR_ANS_INVALID_PARAM;
    }

    size_t slotSize = slots.size();
    if (slotSize > MAX_SLOT_NUM) {
        ANS_LOGE("slotSize over max size");
        return ERR_ANS_INVALID_PARAM;
    }

    return proxy->UpdateSlots(bo, slots);
}

ErrCode AnsNotification::GetAllActiveNotifications(std::vector<sptr<Notification>> &notification)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllActiveNotifications(notification);
}

ErrCode AnsNotification::GetAllActiveNotifications(
    const std::vector<std::string> key, std::vector<sptr<Notification>> &notification)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    if (key.empty()) {
        ANS_LOGE("empty key");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetSpecialActiveNotifications(key, notification);
}

ErrCode AnsNotification::GetActiveNotificationByFilter(const LiveViewFilter &filter,
    sptr<NotificationRequest> &request)
{
    if (filter.bundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    ANS_LOGD("Bundle name %{public}s, uid %{public}d, notification id %{public}d, label %{public}s.",
        filter.bundle.GetBundleName().c_str(), filter.bundle.GetUid(), filter.notificationKey.id,
        filter.notificationKey.label.c_str());

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(filter.bundle));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetActiveNotificationByFilter(bo, filter.notificationKey.id,
        filter.notificationKey.label, filter.userId, filter.extraInfoKeys, request);
}

ErrCode AnsNotification::IsAllowedNotify(const NotificationBundleOption &bundleOption, bool &allowed)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->IsSpecialBundleAllowedNotify(bo, allowed);
}

ErrCode AnsNotification::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationsEnabledForAllBundles(deviceId, enabled);
}

ErrCode AnsNotification::SetNotificationsEnabledForDefaultBundle(const std::string &deviceId, bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationsEnabledForBundle(deviceId, enabled);
}

ErrCode AnsNotification::SetNotificationsEnabledForSpecifiedBundle(
    const NotificationBundleOption &bundleOption, const std::string &deviceId, bool enabled)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetNotificationsEnabledForSpecialBundle(deviceId, bo, enabled, true);
}

ErrCode AnsNotification::SetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalidated bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetShowBadgeEnabledForBundle(bo, enabled);
}

ErrCode AnsNotification::GetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetShowBadgeEnabledForBundle(bo, enabled);
}

ErrCode AnsNotification::GetShowBadgeEnabled(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetShowBadgeEnabled(enabled);
}

ErrCode AnsNotification::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    ANS_LOGI("groupName:%{public}s", groupName.c_str());
    if (groupName.empty()) {
        ANS_LOGE("Invalid group name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelGroup(groupName, instanceKey);
}

ErrCode AnsNotification::RemoveGroupByBundle(
    const NotificationBundleOption &bundleOption, const std::string &groupName)
{
    ANS_LOGI("bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty() || groupName.empty()) {
        ANS_LOGE("Invalid parameter.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->RemoveGroupByBundle(bo, groupName);
}

ErrCode AnsNotification::SetDoNotDisturbDate(const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    auto dndDatePtr = new (std::nothrow) NotificationDoNotDisturbDate(doNotDisturbDate);
    if (dndDatePtr == nullptr) {
        ANS_LOGE("null dndDatePtr");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationDoNotDisturbDate> dndDate(dndDatePtr);
    if (dndDate == nullptr) {
        ANS_LOGE("null dndDate");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetDoNotDisturbDate(dndDate);
}

ErrCode AnsNotification::GetDoNotDisturbDate(NotificationDoNotDisturbDate &doNotDisturbDate)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationDoNotDisturbDate> dndDate = nullptr;
    auto ret = proxy->GetDoNotDisturbDate(dndDate);
    if (ret != ERR_OK) {
        ANS_LOGE("GetDoNotDisturbDate failed.");
        return ret;
    }

    if (!dndDate) {
        ANS_LOGE("Invalid DoNotDisturbDate.");
        return ERR_ANS_NO_MEMORY;
    }

    doNotDisturbDate = *dndDate;
    return ret;
}

ErrCode AnsNotification::AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->AddDoNotDisturbProfiles(profiles);
}

ErrCode AnsNotification::RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->RemoveDoNotDisturbProfiles(profiles);
}

ErrCode AnsNotification::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->DoesSupportDoNotDisturbMode(doesSupport);
}

ErrCode AnsNotification::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
}

ErrCode AnsNotification::PublishContinuousTaskNotification(const NotificationRequest &request)
{
    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the sequence numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    auto pReq = new (std::nothrow) NotificationRequest(request);
    if (pReq == nullptr) {
        ANS_LOGE("null pReq");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationRequest> sptrReq(pReq);
    if (IsNonDistributedNotificationType(sptrReq->GetNotificationType())) {
        sptrReq->SetDistributed(false);
    }
    if (sptrReq == nullptr) {
        ANS_LOGE("null sptrReq");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->PublishContinuousTaskNotification(sptrReq);
}

ErrCode AnsNotification::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGI("notificationId:%{public}d", notificationId);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->CancelContinuousTaskNotification(label, notificationId);
}

ErrCode AnsNotification::IsDistributedEnabled(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsDistributedEnabled(enabled);
}

ErrCode AnsNotification::EnableDistributed(const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->EnableDistributed(enabled);
}

ErrCode AnsNotification::EnableDistributedByBundle(const NotificationBundleOption &bundleOption, const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->EnableDistributedByBundle(bo, enabled);
}

ErrCode AnsNotification::EnableDistributedSelf(const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->EnableDistributedSelf(enabled);
}

ErrCode AnsNotification::IsDistributedEnableByBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->IsDistributedEnableByBundle(bo, enabled);
}

ErrCode AnsNotification::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t remindTypeTemp = -1;
    auto ret = proxy->GetDeviceRemindType(remindTypeTemp);
    remindType = static_cast<NotificationConstant::RemindType>(remindTypeTemp);
    return ret;
}

void AnsNotification::ResetAnsManagerProxy()
{}

void AnsNotification::Reconnect()
{
    ANS_LOGD("called");
    for (int32_t i = 0; i < MAX_RETRY_TIME; i++) {
        // try to connect ans
        sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
            // Sleep 1000 milliseconds before reconnect.
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
            ANS_LOGE("get ans proxy fail, try again.");
            continue;
        }

        ANS_LOGD("get ans proxy success.");
        return;
    }
}

sptr<IAnsManager> AnsNotification::GetAnsManagerProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ANS_LOGE("Failed to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (!remoteObject) {
        ANS_LOGE("Failed to get notification Manager.");
        return nullptr;
    }

    sptr<IAnsManager> proxy = iface_cast<IAnsManager>(remoteObject);
    if ((!proxy) || (!proxy->AsObject())) {
        ANS_LOGE("Failed to get notification Manager's proxy");
        return nullptr;
    }
    return proxy;
}

bool AnsNotification::CanPublishMediaContent(const NotificationRequest &request) const
{
    if (NotificationContent::Type::MEDIA != request.GetNotificationType()) {
        return true;
    }

    if (request.GetContent() == nullptr) {
        ANS_LOGE("Failed to publish notification with null content.");
        return false;
    }

    auto media = std::static_pointer_cast<NotificationMediaContent>(request.GetContent()->GetNotificationContent());
    if (media == nullptr) {
        ANS_LOGE("null media");
        return false;
    }

    auto showActions = media->GetShownActions();
    size_t size = request.GetActionButtons().size();
    for (auto it = showActions.begin(); it != showActions.end(); ++it) {
        if (*it > size) {
            ANS_LOGE("The sequence numbers actions is: %{public}d, the assigned to added action buttons size is: "
                     "%{public}zu.", *it, size);
            return false;
        }
    }

    return true;
}

bool AnsNotification::CanPublishLiveViewContent(const NotificationRequest &request) const
{
    if (!request.IsCommonLiveView()) {
        return true;
    }

    if (request.GetContent() == nullptr) {
        ANS_LOGE("Failed to publish notification with null content.");
        return false;
    }

    auto content = request.GetContent()->GetNotificationContent();
    auto liveView = std::static_pointer_cast<NotificationLiveViewContent>(content);
    if (liveView == nullptr) {
        ANS_LOGE("null liveView");
        return false;
    }

    auto status = liveView->GetLiveViewStatus();
    if (status >= NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT) {
        ANS_LOGE("Invalid status %{public}u.", status);
        return false;
    }

    return true;
}

ErrCode AnsNotification::CheckImageSize(const NotificationRequest &request)
{
    auto littleIcon = request.GetLittleIcon();
    bool collaborateFlag = request.GetDistributedCollaborate();
    if (!collaborateFlag && NotificationRequest::CheckImageOverSizeForPixelMap(littleIcon, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of little icon exceeds limit");
        return ERR_ANS_ICON_OVER_SIZE;
    }

    auto overlayIcon = request.GetOverlayIcon();
    if (overlayIcon && NotificationRequest::CheckImageOverSizeForPixelMap(overlayIcon, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of overlay icon exceeds limit");
        return ERR_ANS_ICON_OVER_SIZE;
    }

    ErrCode err = request.CheckImageSizeForContent(collaborateFlag);
    if (err != ERR_OK) {
        return err;
    }

    auto buttons = request.GetActionButtons();
    for (auto &btn : buttons) {
        if (!btn) {
            continue;
        }
        auto icon = btn->GetIcon();
        if (NotificationRequest::CheckImageOverSizeForPixelMap(icon, MAX_ICON_SIZE)) {
            ANS_LOGE("The size of icon in ActionButton exceeds limit");
            return ERR_ANS_ICON_OVER_SIZE;
        }
    }

    auto users = request.GetMessageUsers();
    for (auto &user : users) {
        if (!user) {
            continue;
        }
        auto icon = user->GetPixelMap();
        if (NotificationRequest::CheckImageOverSizeForPixelMap(icon, MAX_ICON_SIZE)) {
            ANS_LOGE("The size of picture in MessageUser exceeds limit");
            return ERR_ANS_ICON_OVER_SIZE;
        }
    }

    auto bigIcon = request.GetBigIcon();
    if (NotificationRequest::CheckImageOverSizeForPixelMap(bigIcon, MAX_ICON_SIZE)) {
        request.ResetBigIcon();
        ANS_LOGW("The size of big icon exceeds limit");
    }

    return ERR_OK;
}

ErrCode AnsNotification::IsSupportTemplate(const std::string &templateName, bool &support)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsSupportTemplate(templateName, support);
}

bool AnsNotification::IsNonDistributedNotificationType(const NotificationContent::Type &type)
{
    return ((type == NotificationContent::Type::CONVERSATION) ||
        (type == NotificationContent::Type::PICTURE) ||
        (type == NotificationContent::Type::LIVE_VIEW));
}

ErrCode AnsNotification::IsAllowedNotify(const int32_t &userId, bool &allowed)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsSpecialUserAllowedNotify(userId, allowed);
}

ErrCode AnsNotification::SetNotificationsEnabledForAllBundles(const int32_t &userId, bool enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationsEnabledByUser(userId, enabled);
}

ErrCode AnsNotification::RemoveNotifications(const int32_t &userId)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->DeleteAllByUser(userId);
}

ErrCode AnsNotification::SetDoNotDisturbDate(const int32_t &userId,
    const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    auto dndDatePtr = new (std::nothrow) NotificationDoNotDisturbDate(doNotDisturbDate);
    if (dndDatePtr == nullptr) {
        ANS_LOGE("null dndDatePtr");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationDoNotDisturbDate> dndDate(dndDatePtr);
    if (dndDate == nullptr) {
        ANS_LOGE("null dndDate");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetDoNotDisturbDate(dndDate);
}

ErrCode AnsNotification::GetDoNotDisturbDate(const int32_t &userId, NotificationDoNotDisturbDate &doNotDisturbDate)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationDoNotDisturbDate> dndDate = nullptr;
    auto ret = proxy->GetDoNotDisturbDate(dndDate);
    if (ret != ERR_OK) {
        ANS_LOGE("Get DoNotDisturbDate failed.");
        return ret;
    }

    if (!dndDate) {
        ANS_LOGE("Invalid DoNotDisturbDate.");
        return ERR_ANS_NO_MEMORY;
    }

    doNotDisturbDate = *dndDate;
    return ret;
}

ErrCode AnsNotification::SetEnabledForBundleSlot(const NotificationBundleOption &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetEnabledForBundleSlot fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetEnabledForBundleSlot(bo, slotType, enabled, isForceControl);
}

ErrCode AnsNotification::GetEnabledForBundleSlot(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetEnabledForBundleSlot fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->GetEnabledForBundleSlot(bo, slotType, enabled);
}

ErrCode AnsNotification::GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetEnabledForBundleSlotSelf fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetEnabledForBundleSlotSelf(slotType, enabled);
}

ErrCode AnsNotification::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->ShellDump(cmd, bundle, userId, recvUserId, dumpInfo);
}

ErrCode AnsNotification::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetSyncNotificationEnabledWithoutApp(userId, enabled);
}

ErrCode AnsNotification::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetSyncNotificationEnabledWithoutApp(userId, enabled);
}

ErrCode AnsNotification::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetBadgeNumber fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetBadgeNumber(badgeNumber, instanceKey);
}

ErrCode AnsNotification::SetBadgeNumberByBundle(const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Unable to connect to ANS service.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleInfo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundleInfo == nullptr) {
        ANS_LOGE("null bundleInfo");
        return ERR_ANS_NO_MEMORY;
    }
    return proxy->SetBadgeNumberByBundle(bundleInfo, badgeNumber);
}

ErrCode AnsNotification::SetBadgeNumberForDhByBundle(
    const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    ANS_LOGI("info:%{public}s %{public}d %{public}d",
        bundleOption.GetBundleName().c_str(), bundleOption.GetUid(), badgeNumber);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Unable to connect to ANS service.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleInfo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundleInfo == nullptr) {
        ANS_LOGE("null bundleInfo");
        return ERR_ANS_NO_MEMORY;
    }
    return proxy->SetBadgeNumberForDhByBundle(bundleInfo, badgeNumber);
}

ErrCode AnsNotification::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllNotificationEnabledBundles(bundleOption);
}

ErrCode AnsNotification::GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllLiveViewEnabledBundles(bundleOption);
}

ErrCode AnsNotification::GetAllDistribuedEnabledBundles(const std::string& deviceType,
    std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllDistribuedEnabledBundles(deviceType, bundleOption);
}

ErrCode AnsNotification::RegisterPushCallback(
    const sptr<IRemoteObject>& pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->RegisterPushCallback(pushCallback, notificationCheckRequest);
}

ErrCode AnsNotification::UnregisterPushCallback()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->UnregisterPushCallback();
}

ErrCode AnsNotification::SetAdditionConfig(const std::string &key, const std::string &value)
{
    if (key.empty()) {
        ANS_LOGE("Set package config fail: key is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetAdditionConfig(key, value);
}

ErrCode AnsNotification::SetDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty() || deviceType.empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetDistributedEnabledByBundleCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetDistributedEnabledByBundle(bo, deviceType, enabled);
}

ErrCode AnsNotification::SetDistributedBundleOption(
    const std::vector<DistributedBundleOption> &bundles, const std::string &deviceType)
{
    ANS_LOGD("called");
    if (bundles.empty()) {
        ANS_LOGE("Invalid bundles.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<DistributedBundleOption>> bundleOptions;
    for (auto bundle : bundles) {
        sptr<DistributedBundleOption> distributedBundleOption(new (std::nothrow) DistributedBundleOption(bundle));
        bundleOptions.emplace_back(distributedBundleOption);
    }
    return proxy->SetDistributedBundleOption(bundleOptions, deviceType);
}

ErrCode AnsNotification::SetDistributedEnabled(const std::string &deviceType, const bool &enabled)
{
    ANS_LOGD("called");
    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetDistributedEnabled(deviceType, enabled);
}

ErrCode AnsNotification::IsDistributedEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsDistributedEnabled(deviceType, enabled);
}

ErrCode AnsNotification::GetDistributedAbility(int32_t &abilityId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetDistributedAbility(abilityId);
}

ErrCode AnsNotification::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
{
    ANS_LOGD("called");
    if (deviceType.empty() || deviceId.empty()) {
        ANS_LOGE("Invalid deviceType or deviceId.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);
}

ErrCode AnsNotification::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
{
    ANS_LOGD("called");
    if (deviceType.empty() || deviceId.empty()) {
        ANS_LOGE("Invalid deviceType or deviceId.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);
}

ErrCode AnsNotification::IsDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty() || deviceType.empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("IsDistributedEnabledByBundleCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->IsDistributedEnabledByBundle(bo, deviceType, enabled);
}

ErrCode AnsNotification::SetSilentReminderEnabled(const NotificationBundleOption &bundleOption,
    const bool enabled)
{
    ANS_LOGD("enter");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetSilentReminderEnabledCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("Fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SetSilentReminderEnabled(bo, enabled);
}

ErrCode AnsNotification::IsSilentReminderEnabled(const NotificationBundleOption &bundleOption,
    int32_t &enableStatus)
{
    ANS_LOGD("enter");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("IsSilentReminderEnabledCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("Fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->IsSilentReminderEnabled(bo, enableStatus);
}

ErrCode AnsNotification::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetSmartReminderEnabled(deviceType, enabled);
}

ErrCode AnsNotification::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
}

ErrCode AnsNotification::IsDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
}

ErrCode AnsNotification::CancelAsBundleWithAgent(const NotificationBundleOption &bundleOption, const int32_t id)
{
    ANS_LOGI("bundleName:%{public}s,id:%{public}d",
        bundleOption.GetBundleName().c_str(), id);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundle(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundle == nullptr) {
        ANS_LOGE("null bundle");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->CancelAsBundleWithAgent(bundle, id);
}

ErrCode AnsNotification::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsSmartReminderEnabled(deviceType, enabled);
}

ErrCode AnsNotification::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const std::string deviceId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetTargetDeviceStatus(deviceType, status, deviceId);
}

ErrCode AnsNotification::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag, const std::string deviceId, int32_t userId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId);
}

ErrCode AnsNotification::SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    int operatorType, const std::vector<std::string>& bundleList, const std::vector<std::string>& labelList)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetTargetDeviceBundleList(deviceType, deviceId, operatorType, bundleList, labelList);
}

ErrCode AnsNotification::GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
    std::string& deviceId, int32_t& userId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetMutilDeviceStatus fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetMutilDeviceStatus(deviceType, status, deviceId, userId);
}

ErrCode AnsNotification::GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    std::vector<std::string>& bundleList, std::vector<std::string>& labelList)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetTargetDeviceBundleList(deviceType, deviceId, bundleList, labelList);
}

ErrCode AnsNotification::SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
    bool notificaitonEnable, bool liveViewEnable)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetTargetDeviceSwitch(deviceType, deviceId, notificaitonEnable, liveViewEnable);
}

ErrCode AnsNotification::GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetTargetDeviceStatus(deviceType, status);
}

bool AnsNotification::IsValidTemplate(const NotificationRequest &request) const
{
    if (request.GetTemplate() == nullptr) {
        return true;
    }

    std::string name = request.GetTemplate()->GetTemplateName();
    if (strcmp(name.c_str(), DOWNLOAD_TEMPLATE_NAME.c_str()) == 0) {
        std::shared_ptr<AAFwk::WantParams> data = request.GetTemplate()->GetTemplateData();
        if (data ==nullptr || !data->HasParam(DOWNLOAD_FILENAME) || !data->HasParam(DOWNLOAD_TITLE)) {
            ANS_LOGE("No required parameters.");
            return false;
        }
    }

    return true;
}

bool AnsNotification::IsValidDelayTime(const NotificationRequest &request)  const
{
    return request.GetPublishDelayTime() <= MAX_PUBLISH_DELAY_TIME;
}

ErrCode AnsNotification::GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetDoNotDisturbProfile(id, profile);
}

ErrCode AnsNotification::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->AllowUseReminder(bundleName, isAllowUseReminder);
}

void AnsNotification::CreateSubscribeListener(const std::shared_ptr<NotificationSubscriber> &subscriber,
    sptr<SubscriberListener> &listener)
{
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    auto item = subscribers_.find(subscriber);
    if (item != subscribers_.end()) {
        listener = item->second;
        ANS_LOGD("subscriber has listener");
        return;
    }
    listener = new (std::nothrow) SubscriberListener(subscriber);
    if (listener != nullptr) {
        subscribers_[subscriber] = listener;
        ANS_LOGD("CreateSubscribeListener success");
    }
}

void AnsNotification::OnServiceDied()
{
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    for (auto item : subscribers_) {
        item.first->OnDied();
    }
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
ErrCode AnsNotification::RegisterSwingCallback(const std::function<void(bool, int)> swingCbFunc)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterSwingCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    swingCallBackService_ = new(std::nothrow) SwingCallBackService(swingCbFunc);
    if (swingCallBackService_ == nullptr) {
        ANS_LOGE("null swingCallBackService");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->RegisterSwingCallback(swingCallBackService_->AsObject());
}
#endif

ErrCode AnsNotification::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UpdateNotificationTimerByUid fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->UpdateNotificationTimerByUid(uid, isPaused);
}

ErrCode AnsNotification::DisableNotificationFeature(const NotificationDisable &notificationDisable)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("DisableNotificationFeature fail");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    sptr<NotificationDisable> reqPtr = new (std::nothrow) NotificationDisable(notificationDisable);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_NO_MEMORY;
    }
    return proxy->DisableNotificationFeature(reqPtr);
}

ErrCode AnsNotification::DistributeOperation(sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (operationInfo == nullptr || callback == nullptr) {
        ANS_LOGE("null operationInfo or callback");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->DistributeOperation(operationInfo, callback);
}

ErrCode AnsNotification::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->ReplyDistributeOperation(hashCode, result);
}

ErrCode AnsNotification::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    ANS_LOGI("hashCode:%{public}s", hashCode.c_str());
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetNotificationRequestByHashCode(hashCode, notificationRequest);
}

ErrCode AnsNotification::SetHashCodeRule(
    const uint32_t type)
{
    ANS_LOGI("type:%{public}d", type);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetHashCodeRule(type);
}

ErrCode AnsNotification::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllNotificationsBySlotType(notifications, slotType);
}

ErrCode AnsNotification::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetDistributedDevicelist(deviceTypes);
}
}  // namespace Notification
}  // namespace OHOS
