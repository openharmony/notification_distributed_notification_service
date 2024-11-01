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

#define private public
#define protected public
#include "ans_subscriber_stub.h"
#include "ans_subscriber_proxy.h"
#include "ans_inner_errors.h"
#include "ans_notification.h"
#undef private
#undef protected

#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Notification {
class AnsSubscriberStubUnitTest : public testing::Test {
public:
    AnsSubscriberStubUnitTest() {}

    virtual ~AnsSubscriberStubUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

    sptr<AnsSubscriberStub> stub_;
};

void AnsSubscriberStubUnitTest::SetUpTestCase()
{
}

void AnsSubscriberStubUnitTest::TearDownTestCase()
{
}

void AnsSubscriberStubUnitTest::SetUp()
{
    stub_ = new AnsSubscriberStub();
}

void AnsSubscriberStubUnitTest::TearDown()
{
}

/**
* @tc.name: OnRemoteRequest01
* @tc.desc: test descriptor check failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, OnRemoteRequest01, Function | MediumTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool bRet = data.WriteInterfaceToken(u"error descriptor");
    EXPECT_TRUE(bRet) << "write token error";
    uint32_t code = static_cast<uint32_t>(NotificationInterfaceCode::ON_CONNECTED);

    ErrCode res = stub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, OBJECT_NULL) << "descriptor error";
}

/**
* @tc.name: OnRemoteRequest02
* @tc.desc: test code error
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, OnRemoteRequest02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AnsSubscriberStub::GetDescriptor());


    uint32_t code = static_cast<uint32_t>(static_cast<int>(NotificationInterfaceCode::ON_BADGE_ENABLED_CHANGED) + 1);

    ErrCode res = stub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_TRUE(res != NO_ERROR);
}

/**
* @tc.name: OnRemoteRequest04
* @tc.desc: test ON_CONNECTED success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, OnRemoteRequest04, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AnsSubscriberStub::GetDescriptor());
    uint32_t code = static_cast<uint32_t>(NotificationInterfaceCode::ON_CONNECTED);
    ErrCode res = stub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
* @tc.name: HandleOnConnected
* @tc.desc: test HandleOnConnected success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConnected, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnConnected(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
* @tc.name: HandleOnDisconnected
* @tc.desc: test HandleOnDisconnected success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnDisconnected, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnDisconnected(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
* @tc.name: HandleOnConsumedMap01
* @tc.desc: test notification failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedMap01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnConsumedMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedMap02
* @tc.desc: test read existMap failed
* @tc.type: Fun
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedMap02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);

    ErrCode res = stub_->HandleOnConsumedMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedMap03
* @tc.desc: test read NotificationSortingMap failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedMap03, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);
    bool existMap = true;
    data.WriteBool(existMap);

    ErrCode res = stub_->HandleOnConsumedMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedMap04
* @tc.desc: test HandleOnConsumedMap success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedMap04, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);
    bool existMap = true;
    data.WriteBool(existMap);
    sptr<NotificationSortingMap> notificationSortingMap = new NotificationSortingMap();
    data.WriteParcelable(notificationSortingMap);

    ErrCode res = stub_->HandleOnConsumedMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedListMap01
* @tc.desc: test notification failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedListMap01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnConsumedListMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedListMap02
* @tc.desc: test read existMap failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedListMap02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);

    sptr<MockIRemoteObject> remoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, remoteObject);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(remoteObject);
    ASSERT_NE(nullptr, proxy);
    bool isWriteNotificationsSucc = proxy->WriteParcelableVector(notifications, data);
    EXPECT_EQ(isWriteNotificationsSucc, true);

    ErrCode res = stub_->HandleOnConsumedListMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedListMap03
* @tc.desc: test read NotificationSortingMap failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedListMap03, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);

    sptr<MockIRemoteObject> remoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, remoteObject);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(remoteObject);
    ASSERT_NE(nullptr, proxy);
    bool isWriteNotificationsSucc = proxy->WriteParcelableVector(notifications, data);
    EXPECT_EQ(isWriteNotificationsSucc, true);

    bool existMap = true;
    data.WriteBool(existMap);

    ErrCode res = stub_->HandleOnConsumedListMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnConsumedListMap04
* @tc.desc: test HandleOnConsumedListMap success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnConsumedListMap04, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);

    sptr<MockIRemoteObject> remoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, remoteObject);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(remoteObject);
    ASSERT_NE(nullptr, proxy);
    bool isWriteNotificationsSucc = proxy->WriteParcelableVector(notifications, data);
    EXPECT_EQ(isWriteNotificationsSucc, true);

    bool existMap = true;
    data.WriteBool(existMap);
    sptr<NotificationSortingMap> notificationSortingMap = new NotificationSortingMap();
    data.WriteParcelable(notificationSortingMap);

    ErrCode res = stub_->HandleOnConsumedListMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnCanceledMap01
* @tc.desc: test notification failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnCanceledMap01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnCanceledMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnCanceledMap02
* @tc.desc: test read existMap failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnCanceledMap02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);

    ErrCode res = stub_->HandleOnCanceledMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnCanceledMap03
* @tc.desc: test read NotificationSortingMap failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnCanceledMap03, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);
    bool existMap = true;
    data.WriteBool(existMap);

    ErrCode res = stub_->HandleOnCanceledMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnCanceledMap04
* @tc.desc: test read reason failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnCanceledMap04, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);
    bool existMap = true;
    data.WriteBool(existMap);
    sptr<NotificationSortingMap> notificationSortingMap = new NotificationSortingMap();
    data.WriteParcelable(notificationSortingMap);

    ErrCode res = stub_->HandleOnCanceledMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnCanceledMap05
* @tc.desc: test HandleOnCanceledMap success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnCanceledMap05, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<Notification> notification = new Notification();
    data.WriteParcelable(notification);
    bool existMap = true;
    data.WriteBool(existMap);
    sptr<NotificationSortingMap> notificationSortingMap = new NotificationSortingMap();
    data.WriteParcelable(notificationSortingMap);
    int32_t reason = 0;
    data.WriteInt32(reason);

    ErrCode res = stub_->HandleOnCanceledMap(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnUpdated01
* @tc.desc: test notificationMap failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnUpdated01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnUpdated(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnUpdated02
* @tc.desc: test HandleOnUpdated success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnUpdated02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    data.WriteParcelable(notificationMap);

    ErrCode res = stub_->HandleOnUpdated(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
* @tc.name: HandleOnDoNotDisturbDateChange01
* @tc.desc: test callbackData failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnDoNotDisturbDateChange01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnDoNotDisturbDateChange(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnDoNotDisturbDateChange02
* @tc.desc: test HandleOnDoNotDisturbDateChange success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnDoNotDisturbDateChange02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<EnabledNotificationCallbackData> notifcallbackDataication = new EnabledNotificationCallbackData();
    data.WriteParcelable(notifcallbackDataication);

    ErrCode res = stub_->HandleOnDoNotDisturbDateChange(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
* @tc.name: HandleOnEnabledNotificationChanged01
* @tc.desc: test callbackData failed
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnEnabledNotificationChanged01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnEnabledNotificationChanged(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
* @tc.name: HandleOnEnabledNotificationChanged02
* @tc.desc: test HandleOnEnabledNotificationChanged success
* @tc.type: Fun
*/
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnEnabledNotificationChanged02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<EnabledNotificationCallbackData> notifcallbackDataication = new EnabledNotificationCallbackData();
    data.WriteParcelable(notifcallbackDataication);

    ErrCode res = stub_->HandleOnEnabledNotificationChanged(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.name: HandleOnBadgeChanged01
 * @tc.desc: test callbackData failed
 * @tc.type: Fun
 * @tc.require: #I6C2X9
 */
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnBadgeChanged01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode res = stub_->HandleOnBadgeChanged(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleOnBadgeChanged02
 * @tc.desc: test HandleOnBadgeChanged success
 * @tc.type: Fun
 * @tc.require: #I6C2X9
 */
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnBadgeChanged02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    sptr<BadgeNumberCallbackData> badgeData = new BadgeNumberCallbackData();
    data.WriteParcelable(badgeData);

    ErrCode res = stub_->HandleOnBadgeChanged(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.name: HandleOnBadgeEnabledChanged01
 * @tc.desc: test HandleOnBadgeEnabledChanged with empty callback data, expect error code ERR_ANS_PARCELABLE_FAILED.
 * @tc.type: Fun
 */
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnBadgeEnabledChanged01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = stub_->HandleOnBadgeChanged(data, reply);
    EXPECT_EQ(res, ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleOnBadgeEnabledChanged02
 * @tc.desc: test HandleOnBadgeEnabledChanged success with valid parameters, expect error code ERR_OK.
 * @tc.type: Fun
 */
HWTEST_F(AnsSubscriberStubUnitTest, HandleOnBadgeEnabledChanged02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;

    std::string bundleName = "bundleName";
    int32_t uid = 123456;
    bool enabled = false;
    sptr<EnabledNotificationCallbackData> callbackData = new EnabledNotificationCallbackData(bundleName, uid, enabled);
    data.WriteParcelable(callbackData);
    ErrCode res = stub_->HandleOnBadgeChanged(data, reply);
    EXPECT_EQ(res, ERR_OK);
}
}
}
