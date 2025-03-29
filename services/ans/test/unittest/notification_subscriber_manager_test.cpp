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

#include <gtest/gtest.h>
#include <iostream>
#include <thread>

#define private public
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_ans_subscriber.h"
#include "ans_const_define.h"
#include "notification_preferences.h"

#include "ans_inner_errors.h"
#include "ans_subscriber_listener.h"

extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class NotificationSubscriberManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    class TestAnsSubscriber : public NotificationSubscriber {
    public:
        void OnConnected() override
        {}
        void OnDisconnected() override
        {}
        void OnDied() override
        {}
        void OnEnabledNotificationChanged(
            const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
        {
            isCallback_ = true;
        }
        void OnCanceled(const std::shared_ptr<Notification> &request,
            const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
        {
            isCallback_ = true;
        }
        void OnConsumed(const std::shared_ptr<Notification> &request,
            const std::shared_ptr<NotificationSortingMap> &sortingMap) override
        {
            isCallback_ = true;
        }
        void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
        {
            isCallback_ = true;
        }
        void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
        {
            isCallback_ = true;
        }
        void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
        {
            isCallback_ = true;
        }
        void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
        {
            isCallback_ = true;
        }
        void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
            const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
        {
            isCallback_ = true;
        }
        void OnApplicationInfoNeedChanged(const std::string& bundleName) override
        {
            isCallback_ = true;
        }

        ErrCode OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> &operationInfo)
        {
            isCallback_ = true;
            return ERR_OK;
        }

        bool GetCallBack()
        {
            return isCallback_;
        }

        void SetCallBack(bool isCallback)
        {
            isCallback_ = isCallback;
        }
    
    private:
        bool isCallback_;
    };

    static std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager_;
    static TestAnsSubscriber testAnsSubscriber_;
    static sptr<AnsSubscriberInterface> subscriber_;
};

std::shared_ptr<NotificationSubscriberManager> NotificationSubscriberManagerTest::notificationSubscriberManager_ =
    nullptr;
sptr<AnsSubscriberInterface> NotificationSubscriberManagerTest::subscriber_ = nullptr;

void NotificationSubscriberManagerTest::SetUpTestCase()
{
    notificationSubscriberManager_ = NotificationSubscriberManager::GetInstance();
    std::shared_ptr<NotificationSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    subscriber_ = new (std::nothrow) SubscriberListener(testAnsSubscriber);
}

void NotificationSubscriberManagerTest::TearDownTestCase()
{
    subscriber_ = nullptr;
    if (notificationSubscriberManager_ != nullptr) {
        notificationSubscriberManager_->ResetFfrtQueue();
        notificationSubscriberManager_ = nullptr;
    }
}

void NotificationSubscriberManagerTest::SetUp()
{
    MockGetOsAccountLocalIdFromUid(true, 0);
    notificationSubscriberManager_->AddSubscriber(subscriber_, nullptr);
}

void NotificationSubscriberManagerTest::TearDown()
{
    notificationSubscriberManager_->RemoveSubscriber(subscriber_, nullptr);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_001
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test AddSubscriber function, return is ERR_OK.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_001, Function | SmallTest | Level1)
{
    // Test NotifyUpdated function.
    const std::vector<NotificationSorting> sortingList;
    sptr<NotificationSortingMap> map = new NotificationSortingMap(sortingList);
    notificationSubscriberManager_->NotifyUpdated(map);

    // Test AddSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppName("test_bundle");
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber_, info), (int)ERR_OK);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber_, nullptr), (int)ERR_OK);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_002
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test AddSubscriber function when subscriber is nullptr, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_002, Function | SmallTest | Level1)
{
    // Test NotifyDisturbModeChanged function.
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    notificationSubscriberManager_->NotifyDoNotDisturbDateChanged(0, date);

    // Test AddSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_003
 * @tc.name      : ANS_RemoveSubscriber_0100
 * @tc.desc      : Test RemoveSubscriber function, return is ERR_OK.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_003, Function | SmallTest | Level1)
{
    // Test NotifyConsumed function.
    std::vector<NotificationSorting> sortingList;
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap(sortingList);
    notificationSubscriberManager_->NotifyConsumed(notification, notificationMap);

    // Test RemoveSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppName("test_bundle");
    ASSERT_EQ(notificationSubscriberManager_->RemoveSubscriber(subscriber_, info), (int)ERR_OK);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_004
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test RemoveSubscriber function when subscriber is nullptr, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_004, Function | SmallTest | Level1)
{
    // Test NotifyCanceled function.
    std::vector<NotificationSorting> sortingList;
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap(sortingList);
    int deleteReason = 0;
    notificationSubscriberManager_->NotifyCanceled(notification, notificationMap, deleteReason);

    // Test RemoveSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(notificationSubscriberManager_->RemoveSubscriber(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RegisterOnSubscriberAddCallbackTest_001
 * @tc.name      : RegisterOnSubscriberAddCallback and callback is not nullptr
 * @tc.desc      : Test RegisterOnSubscriberAddCallback .
 */
void OnSubscriberAddFake(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &recode) {}
HWTEST_F(NotificationSubscriberManagerTest, RegisterOnSubscriberAddCallbackTest_001, Function | SmallTest | Level1)
{
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(OnSubscriberAddFake, std::placeholders::_1);

    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(callback);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);
}

/**
 * @tc.number    : RegisterOnSubscriberAddCallbackTest_002
 * @tc.name      : RegisterOnSubscriberAddCallback and callback is nullptr
 * @tc.desc      : Test RegisterOnSubscriberAddCallback .
 */
HWTEST_F(NotificationSubscriberManagerTest, RegisterOnSubscriberAddCallbackTest_002, Function | SmallTest | Level1)
{
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(OnSubscriberAddFake, std::placeholders::_1);
    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(callback);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);

    // if callback exist, re-register a nullptr func will fail.
    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(nullptr);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);
}

/**
 * @tc.number    : UnRegisterOnSubscriberAddCallbackTest_001
 * @tc.name      : UnRegisterOnSubscriberAddCallback
 * @tc.desc      : Test UnRegisterOnSubscriberAddCallback .
 */
HWTEST_F(NotificationSubscriberManagerTest, UnRegisterOnSubscriberAddCallbackTest_001, Function | SmallTest | Level1)
{
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(OnSubscriberAddFake, std::placeholders::_1);
    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(callback);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);

    notificationSubscriberManager_->UnRegisterOnSubscriberAddCallback();
    ASSERT_EQ(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_001
 * @tc.name      : BatchNotifyConsumedInner
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_001, Function | SmallTest | Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(1);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("test");
    sptr<Notification> notification = new Notification(request);

    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    notifications.emplace_back(nullptr);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager_->CreateSubscriberRecord(mockSubscriber);
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppName("test");
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager_->AddRecordInfo(record, subscribeInfo);
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, notificationMap, record);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_002
 * @tc.name      : BatchNotifyConsumedInner and params is invalid
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_002, Function | SmallTest | Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(0);
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, nullptr, nullptr);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_003
 * @tc.name      : BatchNotifyConsumedInner and subscriber isn't subscribed to this notification
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_003, Function | SmallTest | Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(0);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("test");
    sptr<Notification> notification = new Notification(request);

    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager_->CreateSubscriberRecord(mockSubscriber);
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppName("test_1");
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager_->AddRecordInfo(record, subscribeInfo);
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, notificationMap, record);
}

/**
 * @tc.number    : BatchNotifyConsumed_001
 * @tc.name      : BatchNotifyConsumed and params is nullptr
 * @tc.desc      : Test BatchNotifyConsumed .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumed_001, Function | SmallTest | Level1)
{
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    sptr<Notification> notification(new Notification(request));
    notifications.emplace_back(notification);
     
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    auto record = notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);

    testAnsSubscriber->SetCallBack(false);
    notificationSubscriberManager.notificationSubQueue_ = nullptr;
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}
 
/**
 * @tc.number    : AddSubscriber001
 * @tc.name      : AddSubscriber and params is nullptr
 * @tc.desc      : Test AddSubscriber .
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriber_001, Function | SmallTest | Level1)
{
    MockGetOsAccountLocalIdFromUid(false, 0);
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    
    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(
        subscriber, nullptr), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddSubscriber_002
 * @tc.name      : AddSubscriber and params is nullptr
 * @tc.desc      : Test AddSubscriber .he
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriber_002, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddDeviceType("current");
    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    info->SetSlotTypes(slotTypes);

    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(subscriber, info), (int)ERR_OK);
    
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    notificationSubscriberManager.NotifyUpdated(notificationMap);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);

    ASSERT_EQ(notificationSubscriberManager.RemoveSubscriber(subscriber, nullptr), (int)ERR_OK);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(102);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_FALSE(res);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_TRUE(res);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSlotTypes(slotTypes);
    subscribeInfo->SetSubscriberUid(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_FALSE(res);
}

// /**
//  * @tc.number    : NotifyConsumed_001
//  * @tc.name      :
//  */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumed_001, Function | SmallTest | Level1)
{
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::OTHER);
    request->SetLabel("label");
    request->SetCreatorUid(0);
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    EXPECT_NE(pictureContent, nullptr);
    pictureContent->SetText("notification text");
    pictureContent->SetTitle("notification title");
    pictureContent->SetBigPicture(nullptr);
    EXPECT_EQ(nullptr, pictureContent->GetBigPicture());
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_NE(content, nullptr);
    request->SetContent(content);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    notificationSubscriberManager.NotifyConsumed(notification, notificationMap);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyBadgeEnabledChanged_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyBadgeEnabledChanged_001, Function | SmallTest | Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber, nullptr), (int)ERR_OK);
     
    sptr<EnabledNotificationCallbackData> callbackData(new EnabledNotificationCallbackData());
    notificationSubscriberManager_->NotifyBadgeEnabledChanged(callbackData);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : ConsumeRecordFilter_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationActionButton> actionButton =
        std::make_shared<NotificationActionButton>();
    std::shared_ptr<NotificationUserInput> userInput =
        std::make_shared<NotificationUserInput>();
    actionButton->AddNotificationUserInput(userInput);

    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->AddActionButton(actionButton);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetFilterType(2);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.ConsumeRecordFilter(record, notification);
    ASSERT_FALSE(res);
}

/**
 * @tc.number    : ConsumeRecordFilter_002
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_002, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationActionButton> actionButton = std::make_shared<NotificationActionButton>();
    std::shared_ptr<NotificationUserInput> userInput = std::make_shared<NotificationUserInput>();
    actionButton->AddNotificationUserInput(userInput);

    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->AddActionButton(actionButton);
    sptr<Notification> notification(new Notification(request));

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetFilterType(4);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.ConsumeRecordFilter(record, notification);
    ASSERT_TRUE(res);
}

/**
 * @tc.number    : ConsumeRecordFilter_003
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<Notification> notification(new Notification(request));

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetFilterType(1);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.ConsumeRecordFilter(record, notification);
    ASSERT_FALSE(res);
}

/**
 * @tc.number    : BatchNotifyCanceledInner_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyCanceledInner_001, Function | SmallTest | Level1)
{
    //build request
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetLabel("label");
    request->SetCreatorUid(0);
    std::shared_ptr<NotificationLiveViewContent> liveViewContentcontent =
        std::make_shared<NotificationLiveViewContent>();
    liveViewContentcontent->SetText("notification text");
    liveViewContentcontent->SetTitle("notification title");
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pixelMap;
    liveViewContentcontent->SetPicture(pixelMap);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContentcontent);
    request->SetContent(content);
    sptr<Notification> notification(new Notification(request));

    sptr<NotificationRequest> requestLocal(new NotificationRequest());
    requestLocal->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    requestLocal->SetLabel("label");
    requestLocal->SetCreatorUid(0);
    std::shared_ptr<NotificationLocalLiveViewContent> liveViewLocalContentcontent =
        std::make_shared<NotificationLocalLiveViewContent>();
    liveViewLocalContentcontent->SetText("notification text");
    liveViewLocalContentcontent->SetTitle("notification title");
    std::shared_ptr<NotificationContent> contentLocal =
        std::make_shared<NotificationContent>(liveViewLocalContentcontent);
    requestLocal->SetContent(contentLocal);
    sptr<Notification> notificationLocal(new Notification(requestLocal));

    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    notifications.push_back(notificationLocal);
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    //brach need nullptr
    notificationSubscriberManager.subscriberRecordList_.push_back(nullptr);

    notificationSubscriberManager.BatchNotifyCanceledInner(notifications, notificationMap, 99);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyDoNotDisturbDateChangedInner_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyDoNotDisturbDateChangedInner_001, Function | SmallTest | Level1)
{
    //build notificationMap
    sptr<NotificationDoNotDisturbDate> date(new NotificationDoNotDisturbDate());

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(101);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyDoNotDisturbDateChangedInner(101, date);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}


/**
 * @tc.number    : NotifyEnabledNotificationChangedInner_002
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledNotificationChangedInner_002, Function | SmallTest | Level1)
{
    //build notificationMap
    sptr<EnabledNotificationCallbackData> date(new EnabledNotificationCallbackData());
    date->SetUid(101);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledNotificationChangedInner(date);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : SetBadgeNumber_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, SetBadgeNumber_001, Function | SmallTest | Level1)
{
    //build notificationMap
    sptr<BadgeNumberCallbackData> date(new BadgeNumberCallbackData());

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.SetBadgeNumber(date);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyApplicationInfoNeedChanged_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyApplicationInfoNeedChanged_001, Function | SmallTest | Level1)
{
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyApplication(true);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyApplicationInfoNeedChanged("test");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

// /**
//  * @tc.number    : IsDeviceFlag_001
//  * @tc.name      :
//  */
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceFlag_001, Function | SmallTest | Level1)
{
    ///build request
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<NotificationLiveViewContent> liveViewContentcontent =
        std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContentcontent);
    request->SetContent(content);
    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(63);
    request->SetFlags(flags);
    
    std::shared_ptr<map<string, std::shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        std::make_shared<map<string, std::shared_ptr<NotificationFlags>>>();

    std::shared_ptr<NotificationFlags> reminderFlags = std::make_shared<NotificationFlags>();
    (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);

    sptr<Notification> notification(new Notification(request));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> subscriberRecord =
       notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    bool wearableFlag = false;
    bool headsetFlag = false;
    bool keyNodeFlag = false;
    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, notification, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_TRUE(keyNodeFlag);
    
    request->SetFlags(nullptr);
    keyNodeFlag = false;
    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, notification, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_FALSE(keyNodeFlag);
}

HWTEST_F(NotificationSubscriberManagerTest, IsDeviceFlag_002, Function | SmallTest | Level1)
{
    ///build request
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    std::shared_ptr<NotificationLiveViewContent> liveViewContentcontent =
        std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content =
        std::make_shared<NotificationContent>(liveViewContentcontent);
    request->SetContent(content);
    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();

    std::shared_ptr<map<string, std::shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        std::make_shared<map<string, std::shared_ptr<NotificationFlags>>>();

    std::shared_ptr<NotificationFlags> reminderFlags = std::make_shared<NotificationFlags>();
    (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);

    sptr<Notification> notification(new Notification(request));
    
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> subscriberRecord =
       notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    bool wearableFlag = false;
    bool headsetFlag = false;
    bool keyNodeFlag = false;
    
    (*notificationFlagsOfDevices)[DEVICE_TYPE_LITE_WEARABLE] = flags;
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddDeviceType(DEVICE_TYPE_LITE_WEARABLE);
    notificationSubscriberManager.AddRecordInfo(subscriberRecord, subscribeInfo);

    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, notification, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_TRUE(wearableFlag);
}

HWTEST_F(NotificationSubscriberManagerTest, IsDeviceFlag_003, Function | SmallTest | Level1)
{
    ///build request
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    std::shared_ptr<NotificationLiveViewContent> liveViewContentcontent =
        std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content =
        std::make_shared<NotificationContent>(liveViewContentcontent);
    request->SetContent(content);
    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    
    std::shared_ptr<map<string, std::shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        std::make_shared<map<string, std::shared_ptr<NotificationFlags>>>();

    std::shared_ptr<NotificationFlags> reminderFlags = std::make_shared<NotificationFlags>();
    (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);

    sptr<Notification> notification(new Notification(request));
    
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> subscriberRecord =
       notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    bool wearableFlag = false;
    bool headsetFlag = false;
    bool keyNodeFlag = false;
    
    (*notificationFlagsOfDevices)[DEVICE_TYPE_WEARABLE] = flags;
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddDeviceType(DEVICE_TYPE_WEARABLE);
    notificationSubscriberManager.AddRecordInfo(subscriberRecord, subscribeInfo);

    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, notification, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_TRUE(wearableFlag);
}

HWTEST_F(NotificationSubscriberManagerTest, IsDeviceFlag_004, Function | SmallTest | Level1)
{
    ///build request
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetLabel("label");
    request->SetCreatorUid(0);
    std::shared_ptr<NotificationLiveViewContent> liveViewContentcontent =
        std::make_shared<NotificationLiveViewContent>();
    liveViewContentcontent->SetText("notification text");
    liveViewContentcontent->SetTitle("notification title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContentcontent);
    request->SetContent(content);
    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    
    std::shared_ptr<map<string, std::shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        std::make_shared<map<string, std::shared_ptr<NotificationFlags>>>();

    std::shared_ptr<NotificationFlags> reminderFlags = std::make_shared<NotificationFlags>();
    (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);

    sptr<Notification> notification(new Notification(request));
    
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> subscriberRecord =
       notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    bool wearableFlag = false;
    bool headsetFlag = false;
    bool keyNodeFlag = false;
    
    (*notificationFlagsOfDevices)[DEVICE_TYPE_HEADSET] = flags;
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddDeviceType(DEVICE_TYPE_HEADSET);
    notificationSubscriberManager.AddRecordInfo(subscriberRecord, subscribeInfo);

    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, notification, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_TRUE(headsetFlag);
    headsetFlag = false;

    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, nullptr, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_FALSE(headsetFlag);

    sptr<Notification> nullNotification(nullptr);
    notificationSubscriberManager.IsDeviceFlag(
        subscriberRecord, nullNotification, wearableFlag, headsetFlag, keyNodeFlag);
    ASSERT_FALSE(headsetFlag);
}

/**
 * @tc.number    : DistributeOperation_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_001, Function | SmallTest | Level1)
{
    sptr<NotificationOperationInfo> operationInfo(new NotificationOperationInfo);
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<AnsSubscriberInterface> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyResponse(true);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.DistributeOperation(operationInfo);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}
/**
 * @tc.number    : OnRemoteDied_001
 * @tc.name      : OnRemoteDied and params is nullptr
 * @tc.desc      : Test OnRemoteDied .
 */
HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_001, Function | SmallTest | Level1)
{
    notificationSubscriberManager_->notificationSubQueue_ = nullptr;
    wptr<IRemoteObject> obj = nullptr;
    notificationSubscriberManager_->OnRemoteDied(obj);
    EXPECT_NE(notificationSubscriberManager_, nullptr);
}
}  // namespace Notification
}  // namespace OHOS
