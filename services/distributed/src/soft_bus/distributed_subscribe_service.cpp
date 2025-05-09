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

#include <sstream>

#include "distributed_service.h"

#include "notification_helper.h"
#include "distributed_client.h"
#include "request_box.h"
#include "state_box.h"
#include "in_process_call_wrapper.h"
#include "distributed_observer_service.h"
#include "notification_subscribe_info.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "distributed_preference.h"
#include "batch_remove_box.h"
#include "ans_inner_errors.h"
#include "remove_box.h"
#include "response_box.h"
#include "analytics_util.h"

namespace OHOS {
namespace Notification {

const std::string DISTRIBUTED_LABEL = "ans_distributed";
const int32_t DEFAULT_FILTER_TYPE = 1;

std::string SubscribeTransDeviceType(uint16_t deviceType)
{
    switch (deviceType) {
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH: {
            return "wearable";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD: {
            return "Pad";
        }
        default:
            return "";
    }
}

void DistributedService::SubscribeNotifictaion(const DistributedDeviceInfo peerDevice)
{
    if (peerDevice_.find(peerDevice.deviceId_) == peerDevice_.end()) {
        ANS_LOGI("Local device no %{public}s %{public}d.", StringAnonymous(peerDevice.deviceId_).c_str(),
            peerDevice.deviceType_);
        return;
    }

    int32_t userId = GetCurrentActiveUserId();
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    subscriber->SetLocalDevice(localDevice_);
    subscriber->SetPeerDevice(peerDevice);
    sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::LIVE_VIEW);
    slotTypes.push_back(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    subscribeInfo->SetSlotTypes(slotTypes);
    subscribeInfo->SetFilterType(DEFAULT_FILTER_TYPE);
    subscribeInfo->AddDeviceType(SubscribeTransDeviceType(peerDevice.deviceType_));
    subscribeInfo->AddAppUserId(userId);
    subscribeInfo->SetNeedNotifyApplication(true);
    subscribeInfo->SetNeedNotifyResponse(true);
    int result = NotificationHelper::SubscribeNotification(subscriber, subscribeInfo);
    if (result == 0) {
        auto iter = subscriberMap_.find(peerDevice.deviceId_);
        if (iter != subscriberMap_.end()) {
            NotificationHelper::UnSubscribeNotification(iter->second);
        }
        subscriberMap_[peerDevice.deviceId_] = subscriber;
        peerDevice_[peerDevice.deviceId_].peerState_ = DeviceState::STATE_ONLINE;
        if (haCallback_ != nullptr) {
            std::string reason = "deviceType: " + std::to_string(localDevice_.deviceType_) +
                                 " ; deviceId: " + StringAnonymous(localDevice_.deviceId_);
            haCallback_(PUBLISH_ERROR_EVENT_CODE, 0, BRANCH3_ID, reason);
        }
    }
    std::string message = "Subscribe: " + StringAnonymous(peerDevice.deviceId_) + " type: " +
        std::to_string(peerDevice.deviceType_) + ", userId: " + std::to_string(userId);
    AnalyticsUtil::GetInstance().SendHaReport(OPERATION_DELETE_BRANCH, result, BRANCH1_ID, message,
        PUBLISH_ERROR_EVENT_CODE);
    ANS_LOGI("Subscribe notification %{public}s %{public}d %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_, userId, result);
}

void DistributedService::UnSubscribeNotifictaion(const std::string &deviceId, uint16_t deviceType)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> subscribeTask = std::bind([&, deviceId, deviceType]() {
        auto deviceIter = peerDevice_.find(deviceId);
        if (deviceIter != peerDevice_.end()) {
            ANS_LOGI("UnSubscribe device %{public}s %{public}d.", StringAnonymous(deviceId).c_str(), deviceType);
            peerDevice_.erase(deviceId);
        }

        auto iter = subscriberMap_.find(deviceId);
        if (iter == subscriberMap_.end()) {
            ANS_LOGI("UnSubscribe invalid %{public}s %{public}d.", StringAnonymous(deviceId).c_str(), deviceType);
            return;
        }

        int32_t result = NotificationHelper::UnSubscribeNotification(iter->second);
        if (result == ERR_OK) {
            subscriberMap_.erase(deviceId);
        }
        std::string message = "UnSubscribe: " + StringAnonymous(deviceId) + " type: " + std::to_string(deviceType);
        AnalyticsUtil::GetInstance().SendHaReport(OPERATION_DELETE_BRANCH, result, BRANCH2_ID, message,
            PUBLISH_ERROR_EVENT_CODE);
        ANS_LOGI("UnSubscribe notification %{public}s %{public}d.", StringAnonymous(deviceId).c_str(), deviceType);
    });
    serviceQueue_->submit(subscribeTask);
}

void DistributedService::SetNotificationContent(const std::shared_ptr<NotificationContent> &content,
    NotificationContent::Type type, std::shared_ptr<NotifticationRequestBox>& requestBox)
{
    if (content == nullptr || content->GetNotificationContent() == nullptr) {
        return;
    }

    ANS_LOGI("Set Notification notification content %{public}d.", type);
    switch (type) {
        case NotificationContent::Type::PICTURE: {
            auto picture = std::static_pointer_cast<NotificationPictureContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(picture->GetTitle());
            requestBox->SetNotificationText(picture->GetText());
            requestBox->SetNotificationAdditionalText(picture->GetAdditionalText());
            requestBox->SetNotificationExpandedTitle(picture->GetExpandedTitle());
            requestBox->SetNotificationBriefText(picture->GetBriefText());
            requestBox->SetNotificationBigPicture(picture->GetBigPicture());
            break;
        }
        case NotificationContent::Type::MULTILINE: {
            auto multiline = std::static_pointer_cast<NotificationMultiLineContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(multiline->GetTitle());
            requestBox->SetNotificationText(multiline->GetText());
            requestBox->SetNotificationAdditionalText(multiline->GetAdditionalText());
            requestBox->SetNotificationExpandedTitle(multiline->GetExpandedTitle());
            requestBox->SetNotificationBriefText(multiline->GetBriefText());
            requestBox->SetNotificationAllLines(multiline->GetAllLines());
            break;
        }
        case NotificationContent::Type::LONG_TEXT: {
            std::shared_ptr<NotificationLongTextContent> contentLong =
                std::static_pointer_cast<NotificationLongTextContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(contentLong->GetTitle());
            requestBox->SetNotificationText(contentLong->GetText());
            requestBox->SetNotificationAdditionalText(contentLong->GetAdditionalText());
            requestBox->SetNotificationExpandedTitle(contentLong->GetExpandedTitle());
            requestBox->SetNotificationBriefText(contentLong->GetBriefText());
            requestBox->SetNotificationLongText(contentLong->GetLongText());
            break;
        }
        case NotificationContent::Type::LIVE_VIEW:
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
        case NotificationContent::Type::BASIC_TEXT:
        default: {
            std::shared_ptr<NotificationBasicContent> contentBasic =
                std::static_pointer_cast<NotificationBasicContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(contentBasic->GetTitle());
            requestBox->SetNotificationText(contentBasic->GetText());
            requestBox->SetNotificationAdditionalText(contentBasic->GetAdditionalText());
            break;
        }
    }
}

void DistributedService::SetNotificationButtons(const sptr<NotificationRequest> notificationRequest,
    NotificationConstant::SlotType slotType, std::shared_ptr<NotifticationRequestBox>& requestBox)
{
    if (notificationRequest == nullptr) {
        return;
    }
    if (slotType == NotificationConstant::SlotType::SOCIAL_COMMUNICATION) {
        auto actionButtons = notificationRequest->GetActionButtons();
        if (actionButtons.empty()) {
            ANS_LOGE("Check actionButtons is null.");
            return;
        }

        std::shared_ptr<NotificationActionButton> button = nullptr;
        for (std::shared_ptr<NotificationActionButton> buttonItem : actionButtons) {
            if (buttonItem != nullptr && buttonItem->GetUserInput() != nullptr &&
                !buttonItem->GetUserInput()->GetInputKey().empty()) {
                button = buttonItem;
                break;
            }
        }
        if (button != nullptr && button->GetUserInput() != nullptr) {
            requestBox->SetNotificationActionName(button->GetTitle());
            requestBox->SetNotificationUserInput(button->GetUserInput()->GetInputKey());
        }
    }
}

void DistributedService::SendNotifictionRequest(const std::shared_ptr<Notification> request,
    const DistributedDeviceInfo& peerDevice, bool isSyncNotification)
{
    std::shared_ptr<NotifticationRequestBox> requestBox = std::make_shared<NotifticationRequestBox>();
    if (request == nullptr || request->GetNotificationRequestPoint() == nullptr) {
        return;
    }

    auto requestPoint = request->GetNotificationRequestPoint();
    ANS_LOGI("Dans OnConsumed %{public}s", requestPoint->Dump().c_str());
    requestBox->SetAutoDeleteTime(requestPoint->GetAutoDeletedTime());
    requestBox->SetFinishTime(requestPoint->GetFinishDeadLine());
    requestBox->SetNotificationHashCode(request->GetKey());
    requestBox->SetSlotType(static_cast<int32_t>(requestPoint->GetSlotType()));
    requestBox->SetContentType(static_cast<int32_t>(requestPoint->GetNotificationType()));
    if (isSyncNotification) {
        requestBox->SetReminderFlag(0);
    } else {
        requestBox->SetReminderFlag(requestPoint->GetFlags()->GetReminderFlags());
    }
    if (request->GetBundleName().empty()) {
        requestBox->SetCreatorBundleName(request->GetCreateBundle());
    } else {
        requestBox->SetCreatorBundleName(request->GetBundleName());
    }
    if (requestPoint->GetBigIcon() != nullptr) {
        requestBox->SetBigIcon(requestPoint->GetBigIcon());
    }
    if (requestPoint->GetOverlayIcon() != nullptr) {
        requestBox->SetOverlayIcon(requestPoint->GetOverlayIcon());
    }
    if (requestPoint->IsCommonLiveView()) {
        std::vector<uint8_t> buffer;
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewEncodeContent(requestPoint, buffer);
        requestBox->SetCommonLiveView(buffer);
    }
    SetNotificationButtons(requestPoint, requestPoint->GetSlotType(), requestBox);
    SetNotificationContent(request->GetNotificationRequestPoint()->GetContent(),
        requestPoint->GetNotificationType(), requestBox);
    if (!requestBox->Serialize()) {
        ANS_LOGW("Dans OnConsumed serialize failed.");
        if (haCallback_ != nullptr) {
            haCallback_(PUBLISH_ERROR_EVENT_CODE, -1, BRANCH3_ID, "serialization failed");
        }
        return;
    }
    DistributedClient::GetInstance().SendMessage(requestBox, TransDataType::DATA_TYPE_BYTES,
        peerDevice.deviceId_, PUBLISH_ERROR_EVENT_CODE);
}

void DistributedService::OnConsumed(const std::shared_ptr<Notification> &request,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, peerDevice, request]() {
        SendNotifictionRequest(request, peerDevice);
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>& notifications,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("check handler is null.");
        return;
    }

    std::ostringstream keysStream;
    std::ostringstream slotTypesStream;
    for (auto notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
            continue;
        }
        ANS_LOGI("dans OnBatchCanceled %{public}s", notification->Dump().c_str());
        keysStream << GetNotificationKey(notification) << ' ';
        slotTypesStream << std::to_string(notification->GetNotificationRequestPoint()->GetSlotType()) << ' ';
    }
    std::string notificationKeys = keysStream.str();
    std::string slotTypes = slotTypesStream.str();

    std::function<void()> task = std::bind([peerDevice, notifications, notificationKeys, slotTypes]() {
        std::shared_ptr<BatchRemoveNotificationBox> batchRemoveBox = std::make_shared<BatchRemoveNotificationBox>();
        if (!notificationKeys.empty()) {
            batchRemoveBox->SetNotificationHashCode(notificationKeys);
        }
        batchRemoveBox->SetNotificationSlotTypes(slotTypes);

        if (!batchRemoveBox->Serialize()) {
            ANS_LOGW("dans OnCanceled serialize failed");
            return;
        }
        DistributedClient::GetInstance().SendMessage(batchRemoveBox, TransDataType::DATA_TYPE_MESSAGE,
            peerDevice.deviceId_, DELETE_ERROR_EVENT_CODE);
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnCanceled(const std::shared_ptr<Notification>& notification,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("check handler is null");
        return;
    }
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
        return;
    }
    std::string notificationKey = GetNotificationKey(notification);
    std::function<void()> task = std::bind([peerDevice, notification, notificationKey]() {
        std::shared_ptr<NotificationRemoveBox> removeBox = std::make_shared<NotificationRemoveBox>();
        ANS_LOGI("dans OnCanceled %{public}s", notification->Dump().c_str());
        removeBox->SetNotificationHashCode(notificationKey);
        removeBox->setNotificationSlotType(notification->GetNotificationRequestPoint()->GetSlotType());
        if (!removeBox->Serialize()) {
            ANS_LOGW("dans OnCanceled serialize failed");
            return;
        }
        DistributedClient::GetInstance().SendMessage(removeBox, TransDataType::DATA_TYPE_MESSAGE,
            peerDevice.deviceId_, DELETE_ERROR_EVENT_CODE);
    });
    serviceQueue_->submit(task);
}

std::string DistributedService::GetNotificationKey(const std::shared_ptr<Notification>& notification)
{
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
        return "";
    }
    std::string notificationKey = notification->GetKey();
    if (notification->GetNotificationRequestPoint()->GetDistributedCollaborate()) {
        size_t pos = notificationKey.find(DISTRIBUTED_LABEL);
        if (pos != std::string::npos) {
            notificationKey.erase(pos, DISTRIBUTED_LABEL.length());
        }
    } else {
        notificationKey = DISTRIBUTED_LABEL + notificationKey;
    }
    return notificationKey;
}

ErrCode DistributedService::OnResponse(
    const std::shared_ptr<NotificationOperationInfo> & operationInfo, const DistributedDeviceInfo& device)
{
    std::shared_ptr<NotificationResponseBox> responseBox = std::make_shared<NotificationResponseBox>();
    ANS_LOGI("dans OnResponse %{public}s", operationInfo->Dump().c_str());
    if (operationInfo == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }
    auto hashCode = operationInfo->GetHashCode();
    if (hashCode.find(DISTRIBUTED_LABEL) == 0) {
        hashCode.erase(0, DISTRIBUTED_LABEL.length());
    }

    OperationType type = operationInfo->GetOperationType();
    if (type == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        if (!responseBox->SetMessageType(NOTIFICATION_RESPONSE_REPLY_SYNC)) {
            ANS_LOGW("dans OnResponse SetMessageType failed");
            return ERR_ANS_TASK_ERR;
        }
        responseBox->SetActionName(operationInfo->GetActionName());
        responseBox->SetUserInput(operationInfo->GetUserInput());
    }

    responseBox->SetMatchType(MatchType::MATCH_SYN);
    responseBox->SetOperationType(static_cast<int32_t>(type));
    responseBox->SetNotificationHashCode(hashCode);
    responseBox->SetOperationEventId(operationInfo->GetEventId());
    responseBox->SetLocalDeviceId(localDevice_.deviceId_);
    if (!responseBox->Serialize()) {
        ANS_LOGW("dans OnResponse serialize failed");
        return ERR_ANS_TASK_ERR;
    }

    auto result = DistributedClient::GetInstance().SendMessage(responseBox, TransDataType::DATA_TYPE_MESSAGE,
        device.deviceId_, MODIFY_ERROR_EVENT_CODE);
    if (result != ERR_OK) {
        ANS_LOGE("dans OnResponse send message failed result: %{public}d", result);
        result = ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return result;
}
}
}
