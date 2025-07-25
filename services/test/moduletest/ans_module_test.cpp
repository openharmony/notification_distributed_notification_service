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
#include <functional>
#include <gtest/gtest.h>

#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#define private public
#include "accesstoken_kit.h"
#include "advanced_notification_service.h"
#include "ans_subscriber_listener.h"
#include "notification_subscriber.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);

typedef std::function<void(const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>)>
    ConsumedFunc;
typedef std::function<void(const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>, int)>
    CanceledFunc;

bool passed = false;
class TestAnsSubscriber : public NotificationSubscriber {
public:
    void OnConnected() override
    {
        if (subscriberCb_ != nullptr) {
            subscriberCb_();
        }
    }
    void OnDisconnected() override
    {
        if (unSubscriberCb_ != nullptr) {
            unSubscriberCb_();
        }
    }
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {
        if (canceledCb_ != nullptr) {
            canceledCb_(request, sortingMap, deleteReason);
        }
    }
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {
        if (consumedCb_ != nullptr) {
            consumedCb_(request, sortingMap);
        }
    }
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}

    ConsumedFunc consumedCb_ = nullptr;
    CanceledFunc canceledCb_ = nullptr;
    std::function<void()> unSubscriberCb_ = nullptr;
    std::function<void()> subscriberCb_ = nullptr;
};

class AnsModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void TestAddSlots();

    static sptr<AdvancedNotificationService> g_advancedNotificationService;
};

sptr<AdvancedNotificationService> AnsModuleTest::g_advancedNotificationService;
void AnsModuleTest::SetUpTestCase()
{
    passed = false;
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    g_advancedNotificationService = OHOS::Notification::AdvancedNotificationService::GetInstance();
}

void AnsModuleTest::TearDownTestCase()
{
    passed = false;
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    if (g_advancedNotificationService != nullptr) {
        g_advancedNotificationService->SelfClean();
    }
}

void AnsModuleTest::SetUp()
{
    passed = false;
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
}

void AnsModuleTest::TearDown()
{
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    passed = false;
}

void AnsModuleTest::TestAddSlots()
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);
}

/**
 * @tc.number    : AnsModuleTest_002
 * @tc.name      : ANS_Module_Test_0200
 * @tc.desc      : Test the function of getting notifications and getting all notifications
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_002, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    TestAddSlots();
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req1->SetLabel(label);
    sptr<NotificationRequest> req2 = new NotificationRequest(2);
    req2->SetLabel("testLabel1");
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppName("bundleName");
    std::vector<sptr<NotificationRequest>> notificationsReqs;
    std::vector<sptr<Notification>> notifications;
    EXPECT_EQ((int)g_advancedNotificationService->Publish(label, req), (int)ERR_OK);
    EXPECT_EQ((int)g_advancedNotificationService->Publish(label, req1), (int)ERR_OK);
    EXPECT_EQ((int)g_advancedNotificationService->Publish("testLabel1", req2), (int)ERR_OK);
    EXPECT_EQ((int)g_advancedNotificationService->GetActiveNotifications(notificationsReqs, ""), (int)ERR_OK);
    uint64_t num;
    g_advancedNotificationService->GetActiveNotificationNums(num);
    EXPECT_EQ(num, 3);
    EXPECT_EQ((int)g_advancedNotificationService->Cancel(2, "testLabel1", ""), (int)ERR_OK);
    EXPECT_EQ((int)g_advancedNotificationService->GetAllActiveNotifications(notifications), (int)ERR_OK);
    EXPECT_EQ((int)notifications.size(), (int)2);
    EXPECT_EQ((int)g_advancedNotificationService->CancelAll(""), (int)ERR_OK);
}

/**
 * @tc.number    : AnsModuleTest_003
 * @tc.name      : ANS_Module_Test_0300
 * @tc.desc      : Test publish notifications when slot not found, add it.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_003, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);
    g_advancedNotificationService->SetNotificationsEnabledForBundle("", false);

    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(true, passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_005
 * @tc.name      : ANS_Module_Test_0500
 * @tc.desc      : Test publish notification when slot type is SERVICE_REMINDER.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_005, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetContent(content2);
    req1->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req1->SetContent(content2);
    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_006
 * @tc.name      : ANS_Module_Test_0600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_006, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_007
 * @tc.name      : ANS_Module_Test_0700
 * @tc.desc      : Test publish notification when slot type is OTHER.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_007, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
            ANS_LOGE("XXXX size %{public}zu", sortingKey.size());
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetContent(content2);
    req1->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req1->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0013
 * @tc.name      : ANS_Module_Test_01300
 * @tc.desc      : Test publish notification when slot type is SOCIAL_COMMUNICATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0013, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds (200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0014
 * @tc.name      : ANS_Module_Test_01400
 * @tc.desc      : Test publish notification when slot type is SOCIAL_COMMUNICATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0014, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("1");
    normalContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0015
 * @tc.name      : ANS_Module_Test_01500
 * @tc.desc      : Test publish notification when slot type is SOCIAL_COMMUNICATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0015, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("1");
    normalContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0017
 * @tc.name      : ANS_Module_Test_01700
 * @tc.desc      : Test publish notification when slot type is SOCIAL_COMMUNICATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0017, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("1");
    normalContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0019
 * @tc.name      : ANS_Module_Test_01900
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0019, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationLongTextContent> longTextContent = std::make_shared<NotificationLongTextContent>();
    longTextContent->SetText("1");
    longTextContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0021
 * @tc.name      : ANS_Module_Test_02100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0021, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            ANS_LOGE("XXXX size %{public}zu", sortingKey.size());
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    pictureContent->SetText("1");
    pictureContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    req->SetContent(content);
    req1->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0023
 * @tc.name      : ANS_Module_Test_02300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0023, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMultiLineContent> contentImpl = std::make_shared<NotificationMultiLineContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0031
 * @tc.name      : ANS_Module_Test_03100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0031, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0033
 * @tc.name      : ANS_Module_Test_03300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0033, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>) {
        if (notification->EnableVibrate()) {
            passed = true;
        }
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slot->SetEnableVibration(true);
    slot->SetVibrationStyle(std::vector<int64_t>(1, 1));
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> contentImpl = std::make_shared<NotificationNormalContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0034
 * @tc.name      : ANS_Module_Test_03400
 * @tc.desc      : Test publish notification when slot type is SOCIAL_COMMUNICATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0034, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>) {
        if (notification->EnableSound()) {
            passed = true;
        }
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slot->SetEnableVibration(true);
    slot->SetSound(Uri("/sound/test.mp3"));
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> contentImpl = std::make_shared<NotificationNormalContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0035
 * @tc.name      : ANS_Module_Test_03500
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0035, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->canceledCb_ = [](const std::shared_ptr<Notification> &request,
                                  const std::shared_ptr<NotificationSortingMap> &sortingMap,
                                  int deleteReason) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Cancel(0, label, "");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0036
 * @tc.name      : ANS_Module_Test_03600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0036, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->canceledCb_ = [](const std::shared_ptr<Notification> &request,
                                  const std::shared_ptr<NotificationSortingMap> &sortingMap,
                                  int deleteReason) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->CancelAll("");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0039
 * @tc.name      : ANS_Module_Test_03900
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0039, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0040
 * @tc.name      : ANS_Module_Test_04000
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0040, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0041
 * @tc.name      : ANS_Module_Test_04100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0041, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0042
 * @tc.name      : ANS_Module_Test_04200
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0042, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0043
 * @tc.name      : ANS_Module_Test_04300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0043, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CUSTOM);
    slot->SetEnableVibration(true);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0049
 * @tc.name      : ANS_Module_Test_04900
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0049, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> socialSlot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> reminderSlot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    sptr<NotificationSlot> contentSlot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    sptr<NotificationSlot> otherSlot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(socialSlot);
    slots.push_back(reminderSlot);
    slots.push_back(contentSlot);
    slots.push_back(otherSlot);

    ASSERT_NE(nullptr, g_advancedNotificationService);
    g_advancedNotificationService->AddSlots(slots);
}

/**
 * @tc.number    : AnsModuleTest_0051
 * @tc.name      : ANS_Module_Test_05100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0051, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::string slotId = slot->GetId();
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    std::vector<sptr<NotificationSlot>> slotsRef {};
    g_advancedNotificationService->GetSlots(slotsRef);
    EXPECT_EQ(1, static_cast<int>(slotsRef.size()));
    std::vector<std::string> slotsId {};
    for (const auto &i : slotsRef) {
        slotsId.push_back(i->GetId());
    }
    g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    g_advancedNotificationService->GetSlots(slotsRef);
    EXPECT_EQ(0, static_cast<int>(slotsRef.size()));
}

/**
 * @tc.number    : AnsModuleTest_0052
 * @tc.name      : ANS_Module_Test_05200
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0052, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    std::vector<sptr<NotificationSlot>> slotsRef {};
    g_advancedNotificationService->GetSlots(slotsRef);
    std::vector<std::string> slotsId {};
    for (const auto &i : slotsRef) {
        slotsId.push_back(i->GetId());
    }
    g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    g_advancedNotificationService->GetSlots(slotsRef);
    EXPECT_EQ(0, static_cast<int>(slotsRef.size()));
}

/**
 * @tc.number    : AnsModuleTest_0054
 * @tc.name      : ANS_Module_Test_05400
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0054, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> socialSlot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> reminderSlot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    sptr<NotificationSlot> contentSlot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    sptr<NotificationSlot> otherSlot = new NotificationSlot(NotificationConstant::SlotType::OTHER);

    slots.push_back(socialSlot);
    slots.push_back(reminderSlot);
    slots.push_back(contentSlot);
    slots.push_back(otherSlot);

    EXPECT_EQ(g_advancedNotificationService->AddSlots(slots), 0);
}

/**
 * @tc.number    : AnsModuleTest_0055
 * @tc.name      : ANS_Module_Test_05500
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0055, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> socialSlot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(socialSlot);
    EXPECT_EQ(g_advancedNotificationService->AddSlots(slots), 0);

    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 0);
}

/**
 * @tc.number    : AnsModuleTest_0056
 * @tc.name      : ANS_Module_Test_05600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0056, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> socialSlot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(socialSlot);
    EXPECT_EQ(g_advancedNotificationService->AddSlots(slots), 0);
    // remove slot group
    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 0);
}

/**
 * @tc.number    : AnsModuleTest_0058
 * @tc.name      : ANS_Module_Test_05800
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0058, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> r, const std::shared_ptr<NotificationSortingMap>) {
        if (r->GetNotificationRequest().GetBadgeNumber() == 1) {
            passed = true;
        }
    };
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slot->EnableBadge(true);
    slots.push_back(slot);
    EXPECT_EQ(g_advancedNotificationService->AddSlots(slots), 0);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    req->SetBadgeNumber(1);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // SetShowBadgeEnabledForBundle true
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName", 0);
    g_advancedNotificationService->SetShowBadgeEnabledForBundle(bundleOption, true);

    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(true, passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_062
 * @tc.name      : ANS_Module_Test_06200
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0062, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetContent(content2);
    req1->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req1->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_063
 * @tc.name      : ANS_Module_Test_06300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0063, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetContent(content2);
    req1->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req1->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_064
 * @tc.name      : ANS_Module_Test_06400
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0064, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->unSubscriberCb_ = []() { passed = true; };
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_065
 * @tc.name      : ANS_Module_Test_06500
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0065, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->unSubscriberCb_ = []() { passed = true; };
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_066
 * @tc.name      : ANS_Module_Test_06600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0066, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->canceledCb_ = [](const std::shared_ptr<Notification> &request,
                                  const std::shared_ptr<NotificationSortingMap> &sortingMap,
                                  int deleteReason) { passed = true; };

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);

    // remove request
    g_advancedNotificationService->Delete("__0_1_bundleName_testLabel_0", NotificationConstant::CANCEL_REASON_DELETE);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_100
 * @tc.name      : ANS_Module_Test_10000
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0100, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // create wantagent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();

    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);

    // set content
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("1");
    normalContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    req->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_101
 * @tc.name      : ANS_Module_Test_10100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0101, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // create wantagent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();

    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { passed = true; };

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetWantAgent(agent);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_102
 * @tc.name      : ANS_Module_Test_10200
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0102, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // create wantagent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();

    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { passed = true; };

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetWantAgent(agent);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_103
 * @tc.name      : ANS_Module_Test_10300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0103, Function | SmallTest | Level1)
{
    // create wantagent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();

    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("a");
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { passed = true; };

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetWantAgent(agent);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_105
 * @tc.name      : ANS_Module_Test_10500
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0105, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> socialSlot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> reminderSlot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    sptr<NotificationSlot> contentSlot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    sptr<NotificationSlot> otherSlot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> customSlot = new NotificationSlot(NotificationConstant::SlotType::CUSTOM);

    slots.push_back(socialSlot);
    slots.push_back(reminderSlot);
    slots.push_back(contentSlot);
    slots.push_back(otherSlot);
    slots.push_back(customSlot);

    g_advancedNotificationService->AddSlots(slots);
    EXPECT_EQ(0, g_advancedNotificationService->AddSlots(slots));
}

/**
 * @tc.number    : AnsModuleTest_106
 * @tc.name      : ANS_Module_Test_10600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0106, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // create wantagent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();

    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            passed = true;
        };

    // set disturb mode
    g_advancedNotificationService->SetNotificationsEnabledForBundle("bundleName", false);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetWantAgent(agent);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_107
 * @tc.name      : ANS_Module_Test_10700
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0107, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);

    // set content
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("1");
    normalContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    req->SetContent(content);
    req1->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);

    // remove request
    g_advancedNotificationService->Delete("_0_1_bundleName_testLabel_0", NotificationConstant::CANCEL_REASON_DELETE);
    g_advancedNotificationService->Delete("_0_1_bundleName_testLabel_1", NotificationConstant::CANCEL_REASON_DELETE);
    uint64_t nums = 0;
    g_advancedNotificationService->GetActiveNotificationNums(nums);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
    EXPECT_NE(g_advancedNotificationService, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_108
 * @tc.name      : ANS_Module_Test_10800
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0108, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriberInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    req->SetNotificationId(0);
    req1->SetNotificationId(1);

    // set content
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("1");
    normalContent->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    req->SetContent(content);
    req1->SetContent(content);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    g_advancedNotificationService->Publish(label, req1);

    // remove request
    g_advancedNotificationService->DeleteAllByUser(0);
    uint64_t nums = 0;
    g_advancedNotificationService->GetActiveNotificationNums(nums);
    EXPECT_EQ(nums, 0);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_110
 * @tc.name      : ANS_Module_Test_11000
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0110, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriber->unSubscriberCb_ = []() { passed = true; };
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);

    // unsubscriber
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(passed, true);
}

/**
 * @tc.number    : AnsModuleTest_111
 * @tc.name      : ANS_Module_Test_11100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0111, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    subscriberInfo->AddAppName("bundleName");
    subscriber->subscriberCb_ = []() { passed = true; };
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
    EXPECT_EQ(passed, true);
}

/**
 * @tc.number    : AnsModuleTest_112
 * @tc.name      : ANS_Module_Test_11200
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0112, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }

            if (sorting1.GetRanking() < sorting2.GetRanking() && notification->EnableLight() &&
                notification->EnableSound() && notification->EnableVibrate()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slot->SetSound(Uri("."));
    slot->SetEnableLight(true);
    slot->SetEnableVibration(true);
    slot->SetVibrationStyle(std::vector<int64_t>(1, 1));
    slot->SetLedLightColor(1);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationMultiLineContent> contentImpl = std::make_shared<NotificationMultiLineContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req1->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_113
 * @tc.name      : ANS_Module_Test_11300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0113, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking() && notification->EnableLight() &&
                notification->EnableSound() && notification->EnableVibrate()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slot->SetSound(Uri("."));
    slot->SetEnableLight(true);
    slot->SetEnableVibration(true);
    slot->SetVibrationStyle(std::vector<int64_t>(1, 1));
    slot->SetLedLightColor(1);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationLongTextContent> contentImpl = std::make_shared<NotificationLongTextContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req1->SetSlotType(NotificationConstant::SlotType::OTHER);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_114
 * @tc.name      : ANS_Module_Test_11400
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0114, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking() && notification->EnableLight() &&
                notification->EnableSound() && notification->EnableVibrate()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slot->SetSound(Uri("."));
    slot->SetEnableLight(true);
    slot->SetEnableVibration(true);
    slot->SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
    slot->SetLedLightColor(1);
    slot->SetVibrationStyle(std::vector<int64_t>(1, 1));
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> contentImpl = std::make_shared<NotificationNormalContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req1->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_116
 * @tc.name      : ANS_Module_Test_11600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0116, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking() && notification->EnableLight() &&
                notification->EnableSound() && notification->EnableVibrate()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slot->SetSound(Uri("."));
    slot->SetEnableLight(true);
    slot->SetEnableVibration(true);
    slot->SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
    slot->SetLedLightColor(1);
    slot->SetVibrationStyle(std::vector<int64_t>(1, 1));
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> contentImpl = std::make_shared<NotificationNormalContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    req1->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_117
 * @tc.name      : ANS_Module_Test_11700
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0117, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            std::vector<std::string> sortingKey = sortingMap->GetKey();

            NotificationSorting sorting1;
            NotificationSorting sorting2;
            if (sortingKey.size() == 2) {
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_0", sorting1);
                sortingMap->GetNotificationSorting("__0_1_bundleName_testLabel_1", sorting2);
            }
            if (sorting1.GetRanking() < sorting2.GetRanking() && notification->EnableLight() &&
                notification->EnableSound() && notification->EnableVibrate()) {
                passed = true;
            }
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slot->SetSound(Uri("."));
    slot->SetEnableLight(true);
    slot->SetEnableVibration(true);
    slot->SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
    slot->SetLedLightColor(1);
    slot->SetVibrationStyle(std::vector<int64_t>(1, 1));
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    std::shared_ptr<NotificationNormalContent> contentImpl = std::make_shared<NotificationNormalContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req1->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req1->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Publish(label, req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_120
 * @tc.name      : ANS_Module_Test_12000
 * @tc.desc      : Test publish notifications when Disturb are not allowed publish.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0120, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    sptr<NotificationSubscribeInfo> subscriberInfo = new NotificationSubscribeInfo();
    g_advancedNotificationService->Subscribe(listener, subscriberInfo);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    std::shared_ptr<NotificationNormalContent> contentImpl = std::make_shared<NotificationNormalContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    g_advancedNotificationService->SetNotificationsEnabledForBundle("bundleName", false);

    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(true, passed);
    g_advancedNotificationService->Unsubscribe(listener, subscriberInfo);
}

/**
 * @tc.number    : AnsModuleTest_0121
 * @tc.name      : ANS_Module_Test_12100
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0121, Function | SmallTest | Level1)
{
    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> socialSlot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> reminderSlot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    sptr<NotificationSlot> contentSlot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    sptr<NotificationSlot> otherSlot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> customSlot = new NotificationSlot(NotificationConstant::SlotType::CUSTOM);

    slots.push_back(socialSlot);
    slots.push_back(reminderSlot);
    slots.push_back(contentSlot);
    slots.push_back(otherSlot);
    slots.push_back(customSlot);

    EXPECT_EQ(g_advancedNotificationService->AddSlots(slots), 0);
    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 0);
    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SERVICE_REMINDER), 0);
    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::CONTENT_INFORMATION), 0);
    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::OTHER), 0);
    EXPECT_EQ(g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::CUSTOM), 0);
}

/**
 * @tc.number    : AnsModuleTest_0122
 * @tc.name      : ANS_Module_Test_12200
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0122, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            passed = true;
        };

    subscriber->canceledCb_ = [](const std::shared_ptr<Notification> &request,
                                  const std::shared_ptr<NotificationSortingMap> &sortingMap,
                                  int deleteReason) { passed = true; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req1->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req1->SetSlotType(NotificationConstant::SlotType::OTHER);

    // publish request

    // remove social slot
    EXPECT_EQ(0, g_advancedNotificationService->RemoveSlotByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION));

    // add slot
    std::vector<sptr<NotificationSlot>> otherSlots;
    slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    otherSlots.push_back(slot);
    EXPECT_EQ(0, g_advancedNotificationService->AddSlots(otherSlots));

    EXPECT_FALSE(passed);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_0123
 * @tc.name      : ANS_Module_Test_12300
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0123, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    int ret = 0;
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ = [&ret](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { ret++; };
    subscriber->canceledCb_ = [](const std::shared_ptr<Notification> &request,
                                  const std::shared_ptr<NotificationSortingMap> &sortingMap,
                                  int deleteReason) { passed = true; };
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION));
    slots.push_back(new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER));
    slots.push_back(new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION));
    slots.push_back(new NotificationSlot(NotificationConstant::SlotType::OTHER));
    slots.push_back(new NotificationSlot(NotificationConstant::SlotType::CUSTOM));
    EXPECT_EQ(g_advancedNotificationService->AddSlots(slots), 0);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    sptr<NotificationRequest> req2 = new NotificationRequest(2);
    sptr<NotificationRequest> req3 = new NotificationRequest(3);
    sptr<NotificationRequest> req4 = new NotificationRequest(4);

    req->SetLabel("testLabel");
    req1->SetLabel("testLabel");
    req2->SetLabel("testLabel");
    req3->SetLabel("testLabel");
    req4->SetLabel("testLabel");

    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req1->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    req2->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req3->SetSlotType(NotificationConstant::SlotType::OTHER);
    req4->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    req->SetContent(content2);
    req1->SetContent(content2);
    req2->SetContent(content2);
    req3->SetContent(content2);
    req4->SetContent(content2);

    g_advancedNotificationService->Publish("testLabel", req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(ret, 1);
    g_advancedNotificationService->Publish("testLabel", req1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(ret, 2);
    g_advancedNotificationService->Publish("testLabel", req2);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(ret, 3);
    g_advancedNotificationService->Publish("testLabel", req3);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(ret, 4);
    g_advancedNotificationService->Publish("testLabel", req4);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(ret, 5);
    g_advancedNotificationService->DeleteAllByUser(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0124
 * @tc.name      : ANS_Module_Test_12400
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0124, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            passed = true;
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationMediaContent> contentImpl = std::make_shared<NotificationMediaContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0125
 * @tc.name      : ANS_Module_Test_12500
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0125, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            passed = true;
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);
    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0126
 * @tc.name      : ANS_Module_Test_12600
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0126, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            passed = true;
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slots.push_back(slot);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    std::shared_ptr<NotificationPictureContent> contentImpl = std::make_shared<NotificationPictureContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(contentImpl);
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);

    // publish request
    g_advancedNotificationService->Publish(label, req);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0127
 * @tc.name      : ANS_Module_Test_12700
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0127, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    const int EXPECT_REQUST_NUM = 2;

    int ret = 0;
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ = [&ret](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { ret++; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slots.push_back(slot);
    slots.push_back(slot1);
    g_advancedNotificationService->AddSlots(slots);

    // create content
    std::shared_ptr<NotificationPictureContent> contentImpl = std::make_shared<NotificationPictureContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> pictureContent = std::make_shared<NotificationContent>(contentImpl);

    std::shared_ptr<NotificationLongTextContent> contentImpl1 = std::make_shared<NotificationLongTextContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> longTextContent = std::make_shared<NotificationContent>(contentImpl);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req->SetContent(pictureContent);
    req1->SetLabel(label);
    req1->SetContent(longTextContent);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req1->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);

    // publish
    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_advancedNotificationService->Publish(label, req1), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_EQ(ret, EXPECT_REQUST_NUM);
}

/**
 * @tc.number    : AnsModuleTest_0128
 * @tc.name      : ANS_Module_Test_12800
 * @tc.desc      : Test publish notification when slot type is CONTENT_INFORMATION.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0128, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    const int EXPECT_REQUST_NUM = 2;

    int ret = 0;
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ = [&ret](const std::shared_ptr<Notification> notification,
                                  const std::shared_ptr<NotificationSortingMap>
                                      sortingMap) { ret++; };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    slots.push_back(slot1);
    g_advancedNotificationService->AddSlots(slots);

    // create content
    std::shared_ptr<NotificationPictureContent> contentImpl = std::make_shared<NotificationPictureContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> pictureContent = std::make_shared<NotificationContent>(contentImpl);

    std::shared_ptr<NotificationLongTextContent> contentImpl1 = std::make_shared<NotificationLongTextContent>();
    contentImpl->SetText("1");
    contentImpl->SetTitle("1");
    std::shared_ptr<NotificationContent> longTextContent = std::make_shared<NotificationContent>(contentImpl);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    sptr<NotificationRequest> req1 = new NotificationRequest(1);
    req->SetLabel(label);
    req->SetContent(pictureContent);
    req1->SetLabel(label);
    req1->SetContent(longTextContent);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req1->SetSlotType(NotificationConstant::SlotType::OTHER);

    // publish
    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_advancedNotificationService->Publish(label, req1), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_EQ(ret, EXPECT_REQUST_NUM);
}

/**
 * @tc.number    : AnsModuleTest_0130
 * @tc.name      : ANS_Module_Test_13000
 * @tc.desc      : Test publish notification when slot type is OTHER.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0130, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ =
        [](const std::shared_ptr<Notification> notification, const std::shared_ptr<NotificationSortingMap> sortingMap) {
            EXPECT_FALSE(notification->EnableVibrate());
            EXPECT_FALSE(notification->EnableSound());
        };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    slot->SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
    slot->SetEnableVibration(true);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel(label);
    // publish
    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
}

/**
 * @tc.number    : AnsModuleTest_0131
 * @tc.name      : ANS_Module_Test_13100
 * @tc.desc      : Test publish notification when cancel a  notification.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0131, Function | SmallTest | Level1)
{
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->canceledCb_ = [](const std::shared_ptr<Notification> &request,
                                  const std::shared_ptr<NotificationSortingMap> &sortingMap,
                                  int deleteReason) { passed = true; };
    g_advancedNotificationService->Cancel(1, "1", "");
    g_advancedNotificationService->Unsubscribe(listener, nullptr);
    EXPECT_EQ(false, passed);
}

/**
 * @tc.number    : AnsModuleTest_0132
 * @tc.name      : ANS_Module_Test_13200
 * @tc.desc      : Test publish notifications when Dnd type is NONE.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0132, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    EXPECT_EQ(g_advancedNotificationService->Subscribe(listener, nullptr), ERR_OK);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    EXPECT_EQ(g_advancedNotificationService->SetDoNotDisturbDate(100, date), ERR_OK);

    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_advancedNotificationService->Unsubscribe(listener, nullptr), ERR_OK);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0133
 * @tc.name      : ANS_Module_Test_13300
 * @tc.desc      : Test publish notifications when Dnd type is ONCE.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0133, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    EXPECT_EQ(g_advancedNotificationService->Subscribe(listener, nullptr), ERR_OK);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);
    EXPECT_EQ(g_advancedNotificationService->SetDoNotDisturbDate(100, date), ERR_OK);

    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_advancedNotificationService->Unsubscribe(listener, nullptr), ERR_OK);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0134
 * @tc.name      : ANS_Module_Test_13400
 * @tc.desc      : Test publish notifications when Dnd type is DAILY.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0134, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    EXPECT_EQ(g_advancedNotificationService->SetDoNotDisturbDate(100, date), ERR_OK);

    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_advancedNotificationService->Unsubscribe(listener, nullptr), ERR_OK);
    EXPECT_TRUE(passed);
}

/**
 * @tc.number    : AnsModuleTest_0135
 * @tc.name      : ANS_Module_Test_13500
 * @tc.desc      : Test publish notifications when Dnd type is CLEARLY.
 */
HWTEST_F(AnsModuleTest, AnsModuleTest_0135, Function | SmallTest | Level1)
{
    ASSERT_EQ(g_advancedNotificationService->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
    // subscriber
    std::shared_ptr<TestAnsSubscriber> subscriber = std::make_shared<TestAnsSubscriber>();
    std::shared_ptr<NotificationSubscriber> ptr = std::static_pointer_cast<NotificationSubscriber>(subscriber);
    auto listener = new (std::nothrow) SubscriberListener(ptr);
    g_advancedNotificationService->Subscribe(listener, nullptr);
    subscriber->consumedCb_ = [](const std::shared_ptr<Notification>, const std::shared_ptr<NotificationSortingMap>) {
        passed = true;
    };

    // add slot
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot0);
    g_advancedNotificationService->AddSlots(slots);

    // create request
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(0);
    req->SetLabel(label);
    req->SetStatusBarText("text");
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    req->SetContent(content2);

    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::CLEARLY, beginDate, endDate);
    EXPECT_EQ(g_advancedNotificationService->SetDoNotDisturbDate(100, date), ERR_OK);

    EXPECT_EQ(g_advancedNotificationService->Publish(label, req), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_advancedNotificationService->Unsubscribe(listener, nullptr), ERR_OK);
    EXPECT_TRUE(passed);
}
} // namespace Notification
} // namespace OHOS
