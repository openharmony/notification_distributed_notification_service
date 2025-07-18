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

#include <gtest/gtest.h>

#include "ans_inner_errors.h"
#include "ans_ut_constant.h"
#define private public
#define protected public
#include "notification_preferences.h"
#include "notification_preferences_database.h"
#include "advanced_notification_service.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);

class NotificationPreferencesTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase()
    {
        if (advancedNotificationService_ != nullptr) {
            advancedNotificationService_->SelfClean();
        }
    }

    void SetUp() {};
    void TearDown();

    void TestAddNotificationSlot();
    void TestAddNotificationSlot(NotificationPreferencesInfo &info);

    static sptr<NotificationBundleOption> bundleOption_;
    static sptr<NotificationBundleOption> noExsitbundleOption_;
    static sptr<NotificationBundleOption> bundleEmptyOption_;

protected:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<NotificationBundleOption> NotificationPreferencesTest::bundleOption_ =
    new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
sptr<NotificationBundleOption> NotificationPreferencesTest::noExsitbundleOption_ =
    new NotificationBundleOption(std::string("notExsitBundleName"), NON_SYSTEM_APP_UID);
sptr<NotificationBundleOption> NotificationPreferencesTest::bundleEmptyOption_ =
    new NotificationBundleOption(std::string(), NON_SYSTEM_APP_UID);
sptr<AdvancedNotificationService> NotificationPreferencesTest::advancedNotificationService_ =
    AdvancedNotificationService::GetInstance();

void NotificationPreferencesTest::TearDown()
{
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
}

void NotificationPreferencesTest::TestAddNotificationSlot()
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots);
}

void NotificationPreferencesTest::TestAddNotificationSlot(NotificationPreferencesInfo &info)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    NotificationPreferences::GetInstance()->CheckSlotForCreateSlot(bundleOption_, slot, info);
}

/**
 * @tc.number    : AddNotificationSlots_00100
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB , return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots), (int)ERR_OK);
}

/**
 * @tc.number    : AddNotificationSlots_00200
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when bundleName is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleEmptyOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddNotificationSlots_00300
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when slots is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddNotificationSlots_00400
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when slot is nullptr in vector, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00400, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = nullptr;
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST);
}

/**
 * @tc.number    : AddNotificationSlots_00500
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when slots is same, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot1);
    slots.push_back(slot2);

    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots), (int)ERR_OK);
}

/**
 * @tc.number    : AddNotificationSlots_00600
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB , return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00600, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(nullptr, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationSlot_00100
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB , return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::OTHER),
        (int)ERR_OK);
}

/**
 * @tc.number    : RemoveNotificationSlot_00200
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB when bundle name is null, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationSlot(
                  bundleEmptyOption_, NotificationConstant::SlotType::OTHER),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationSlot_00300
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB when bundle name does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00300, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationSlot(
                  noExsitbundleOption_, NotificationConstant::SlotType::OTHER),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationSlot_00400
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB when slot type does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00400, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::SERVICE_REMINDER),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationSlot_00500
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB , return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00500, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationSlot(
                  nullptr, NotificationConstant::SlotType::OTHER),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00100
 * @tc.name      :
 * @tc.desc      : Remove notification for bundle from disturbe DB, return is ERR_OK;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationForBundle(bundleOption_), (int)ERR_OK);
    advancedNotificationService_->OnBundleRemoved(bundleOption_);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00200
 * @tc.name      :
 * @tc.desc      :  Remove notification for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationForBundle(bundleEmptyOption_),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00300
 * @tc.name      :
 * @tc.desc      :  Remove notification for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00300, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationForBundle(noExsitbundleOption_),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00400
 * @tc.name      :
 * @tc.desc      :  Remove notification for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00400, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationForBundle(nullptr),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : UpdateNotificationSlots_00100
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots), (int)ERR_OK);
    std::string des("This is a description.");
    slot->SetDescription(des);
    slots.clear();
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->UpdateNotificationSlots(bundleOption_, slots), (int)ERR_OK);
}

/**
 * @tc.number    : UpdateNotificationSlots_00200
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when bundleName is null, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->UpdateNotificationSlots(bundleEmptyOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : UpdateNotificationSlots_00300
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when slots is null, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->UpdateNotificationSlots(bundleOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : UpdateNotificationSlots_00400
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when bundle does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00400, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->UpdateNotificationSlots(noExsitbundleOption_, slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : UpdateNotificationSlots_00500
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when slot type does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->UpdateNotificationSlots(noExsitbundleOption_, slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : UpdateNotificationSlots_00600
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when bundleName is null, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00600, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->UpdateNotificationSlots(nullptr, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlot_00100
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    sptr<NotificationSlot> slot;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_OK);
}

/**
 * @tc.number    : GetNotificationSlot_00200
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlot(
                  bundleEmptyOption_, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlot_00300
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when slot type does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00300, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    sptr<NotificationSlot> slot;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::CONTENT_INFORMATION, slot),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : GetNotificationSlot_00400
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when bundle name does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00400, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    sptr<NotificationSlot> slot;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlot(
                  noExsitbundleOption_, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : GetNotificationSlot_00500
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlot(
                  nullptr, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationAllSlots_00100
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB after add a notification slot, return is ERR_OK, get all
 * notifications size is 1.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    std::vector<sptr<NotificationSlot>> slotsResult;
    ASSERT_EQ(
        (int)NotificationPreferences::GetInstance()->GetNotificationAllSlots(bundleOption_, slotsResult), (int)ERR_OK);
    ASSERT_EQ((int)slotsResult.size(), 1);
}

/**
 * @tc.number    : GetNotificationAllSlots_00200
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB after add some notification slot, return is ERR_OK, get
 * all notifications size is the same of adding notifications size.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot1);
    slots.push_back(slot2);
    NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption_, slots);

    std::vector<sptr<NotificationSlot>> slotsResult;
    ASSERT_EQ(
        (int)NotificationPreferences::GetInstance()->GetNotificationAllSlots(bundleOption_, slotsResult), (int)ERR_OK);
    ASSERT_EQ((int)slotsResult.size(), 2);
}

/**
 * @tc.number    : GetNotificationAllSlots_00300
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slotsResult;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationAllSlots(bundleEmptyOption_, slotsResult),
        (int)ERR_ANS_INVALID_PARAM);
    ASSERT_EQ((int)slotsResult.size(), 0);
}

/**
 * @tc.number    : GetNotificationAllSlots_00400
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB when bundle name does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00400, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slotsResult;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationAllSlots(noExsitbundleOption_, slotsResult),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
    ASSERT_EQ((int)slotsResult.size(), 0);
    ErrCode result = advancedNotificationService_->GetSlots(slotsResult);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number    : GetNotificationAllSlots_00500
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00500, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slotsResult;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationAllSlots(nullptr, slotsResult),
        (int)ERR_ANS_INVALID_PARAM);
    ASSERT_EQ((int)slotsResult.size(), 0);
}

/**
 * @tc.number    : SetShowBadge_00100
 * @tc.name      :
 * @tc.desc      : Set bundle show badge into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetShowBadge_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetShowBadge(bundleOption_, true), (int)ERR_OK);
}

/**
 * @tc.number    : SetShowBadge_00200
 * @tc.name      :
 * @tc.desc      : Set bundle show badge into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetShowBadge_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetShowBadge(bundleEmptyOption_, true),
        (int)ERR_ANS_INVALID_PARAM);
    auto result = bundleEmptyOption_->GetBundleName();
    ASSERT_EQ(result, "");
}

/**
 * @tc.number    : SetShowBadge_00300
 * @tc.name      :
 * @tc.desc      : Set bundle show badge into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetShowBadge_00300, Function | SmallTest | Level1)
{
    ASSERT_EQ(
        (int)NotificationPreferences::GetInstance()->SetShowBadge(nullptr, true), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : IsShowBadge_00100
 * @tc.name      :
 * @tc.desc      : Get bunlde show badge from disturbe DB , return is ERR_OK and show badge is true.
 */
HWTEST_F(NotificationPreferencesTest, IsShowBadge_00100, Function | SmallTest | Level1)
{
    bool enable = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetShowBadge(bundleOption_, true), (int)ERR_OK);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->IsShowBadge(bundleOption_, enable), (int)ERR_OK);
    EXPECT_TRUE(enable);
}

/**
 * @tc.number    : IsShowBadge_00200
 * @tc.name      :
 * @tc.desc      : Get bunlde show badge from disturbe DB when bundle name is null, return is ERR_OK and show badge is
 * true.
 */
HWTEST_F(NotificationPreferencesTest, IsShowBadge_00200, Function | SmallTest | Level1)
{
    bool enable = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->IsShowBadge(bundleEmptyOption_, enable),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : IsShowBadge_00300
 * @tc.name      :
 * @tc.desc      : Get bunlde show badge from disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, IsShowBadge_00300, Function | SmallTest | Level1)
{
    bool enable = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->IsShowBadge(nullptr, enable),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetImportance_00100
 * @tc.name      :
 * @tc.desc      : Set bundle importance into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetImportance_00100, Function | SmallTest | Level1)
{
    int importance = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetImportance(bundleOption_, importance), (int)ERR_OK);
}

/**
 * @tc.number    : SetImportance_00200
 * @tc.name      :
 * @tc.desc      : Set bundle importance into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetImportance_00200, Function | SmallTest | Level1)
{
    int importance = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetImportance(bundleEmptyOption_, importance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetImportance_00300
 * @tc.name      :
 * @tc.desc      : Set bundle importance into disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetImportance_00300, Function | SmallTest | Level1)
{
    int importance = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetImportance(nullptr, importance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetImportance_00100
 * @tc.name      :
 * @tc.desc      : Get bundle importance from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetImportance_00100, Function | SmallTest | Level1)
{
    int importance = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetImportance(bundleOption_, importance), (int)ERR_OK);
    int getImportance = 0;

    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetImportance(bundleOption_, getImportance), (int)ERR_OK);
    ASSERT_EQ(getImportance, 1);
}

/**
 * @tc.number    : GetImportance_00200
 * @tc.name      :
 * @tc.desc      : Get bundle importance from disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetImportance_00200, Function | SmallTest | Level1)
{
    int getImportance = 0;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetImportance(bundleEmptyOption_, getImportance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetImportance_00300
 * @tc.name      :
 * @tc.desc      : Get bundle importance from disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetImportance_00300, Function | SmallTest | Level1)
{
    int getImportance = 0;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetImportance(nullptr, getImportance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetTotalBadgeNums_00100
 * @tc.name      :
 * @tc.desc      : Set total badge nums into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetTotalBadgeNums_00100, Function | SmallTest | Level1)
{
    int num = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetTotalBadgeNums(bundleOption_, num), (int)ERR_OK);
}

/**
 * @tc.number    : SetTotalBadgeNums_00200
 * @tc.name      :
 * @tc.desc      : Set total badge nums into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetTotalBadgeNums_00200, Function | SmallTest | Level1)
{
    int num = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetTotalBadgeNums(bundleEmptyOption_, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetTotalBadgeNums_00300
 * @tc.name      :
 * @tc.desc      : Set total badge nums into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetTotalBadgeNums_00300, Function | SmallTest | Level1)
{
    int num = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetTotalBadgeNums(nullptr, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetTotalBadgeNums_00100
 * @tc.name      :
 * @tc.desc      : Get total badge nums from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetTotalBadgeNums_00100, Function | SmallTest | Level1)
{
    int num = 1;
    NotificationPreferences::GetInstance()->SetTotalBadgeNums(bundleOption_, num);
    int totalBadgeNum = 0;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetTotalBadgeNums(bundleOption_, totalBadgeNum),
        (int)ERR_OK);
    ASSERT_EQ(totalBadgeNum, num);
}

/**
 * @tc.number    : GetTotalBadgeNums_00200
 * @tc.name      :
 * @tc.desc      : Get total badge nums from disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetTotalBadgeNums_00200, Function | SmallTest | Level1)
{
    int totalBadgeNum = 0;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetTotalBadgeNums(bundleEmptyOption_, totalBadgeNum),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetTotalBadgeNums_00300
 * @tc.name      :
 * @tc.desc      : Get total badge nums from disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetTotalBadgeNums_00300, Function | SmallTest | Level1)
{
    int totalBadgeNum = 0;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetTotalBadgeNums(nullptr, totalBadgeNum),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetNotificationsEnabledForBundle_00100
 * @tc.name      :
 * @tc.desc      : Set notification enable for bundle into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabledForBundle_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundleOption_, false),
        (int)ERR_OK);
}

/**
 * @tc.number    : SetNotificationsEnabledForBundle_00200
 * @tc.name      :
 * @tc.desc      : Set notification enable for bundle into disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabledForBundle_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundleEmptyOption_, false),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetNotificationsEnabledForBundle_00300
 * @tc.name      :
 * @tc.desc      : Set notification enable for bundle into disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabledForBundle_00300, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(nullptr, false),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationsEnabledForBundle_00100
 * @tc.name      :
 * @tc.desc      : Get notification enable for bundle from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabledForBundle_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundleOption_, false),
        (int)ERR_OK);
    bool enabled = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundleOption_, enabled),
        (int)ERR_OK);
    EXPECT_FALSE(enabled);
}

/**
 * @tc.number    : GetNotificationsEnabledForBundle_00200
 * @tc.name      :
 * @tc.desc      : Get notification enable for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabledForBundle_00200, Function | SmallTest | Level1)
{
    bool enabled = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundleEmptyOption_,
        enabled), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationsEnabledForBundle_00300
 * @tc.name      :
 * @tc.desc      : Get notification enable for bundle from disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabledForBundle_00300, Function | SmallTest | Level1)
{
    bool enabled = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(nullptr, enabled),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetNotificationsEnabled_00100
 * @tc.name      :
 * @tc.desc      : Set enable notification into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabled_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabled(100, true), (int)ERR_OK);
}

/**
 * @tc.number    : SetNotificationsEnabled_00200
 * @tc.name      :
 * @tc.desc      : Set enable notification into disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabled_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabled(TEST_SUBSCRIBE_USER_INIT, true),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationsEnabled_00100
 * @tc.name      :
 * @tc.desc      : Get enable notification from disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabled_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabled(100, true), (int)ERR_OK);
    bool enable = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationsEnabled(100, enable), (int)ERR_OK);
    EXPECT_TRUE(enable);
}

/**
 * @tc.number    : GetNotificationsEnabled_00200
 * @tc.name      :
 * @tc.desc      : Same user can get enable setting, different user can not get.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabled_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetNotificationsEnabled(100, true), (int)ERR_OK);
    bool enable = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationsEnabled(100, enable), (int)ERR_OK);
    EXPECT_TRUE(enable);

    enable = false;
    ASSERT_EQ(
        (int)NotificationPreferences::GetInstance()->GetNotificationsEnabled(101, enable), (int)ERR_ANS_INVALID_PARAM);
    EXPECT_FALSE(enable);
}

/**
 * @tc.number    : GetNotificationsEnabled_00300
 * @tc.name      :
 * @tc.desc      : Get enable notification from disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabled_00300, Function | SmallTest | Level1)
{
    bool enable = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationsEnabled(TEST_SUBSCRIBE_USER_INIT, enable),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetDoNotDisturbDate_00100
 * @tc.name      :
 * @tc.desc      : Set disturbe mode into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, SetDoNotDisturbDate_00100, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);

    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetDoNotDisturbDate(SYSTEM_APP_UID, date), (int)ERR_OK);
}

/**
 * @tc.number    : SetDoNotDisturbDate_00200
 * @tc.name      :
 * @tc.desc      : Set disturbe mode into disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, SetDoNotDisturbDate_00200, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);

    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetDoNotDisturbDate(TEST_SUBSCRIBE_USER_INIT, date),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetDoNotDisturbDate_00100
 * @tc.name      :
 * @tc.desc      : Get disturbe mode from disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbDate_00100, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetDoNotDisturbDate(SYSTEM_APP_UID, date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> getDate;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetDoNotDisturbDate(SYSTEM_APP_UID, getDate), (int)ERR_OK);
    ASSERT_EQ(getDate->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    ASSERT_EQ(getDate->GetBeginDate(), beginDate);
    ASSERT_EQ(getDate->GetEndDate(), endDate);
}

/**
 * @tc.number    : GetDoNotDisturbDate_00200
 * @tc.name      :
 * @tc.desc      : Same user can get DoNotDisturbDate setting, different user can not get.
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbDate_00200, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetDoNotDisturbDate(SYSTEM_APP_UID, date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> getDate;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetDoNotDisturbDate(SYSTEM_APP_UID, getDate), (int)ERR_OK);
    ASSERT_EQ(getDate->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    ASSERT_EQ(getDate->GetBeginDate(), beginDate);
    ASSERT_EQ(getDate->GetEndDate(), endDate);

    sptr<NotificationDoNotDisturbDate> getExsitDate;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetDoNotDisturbDate(
        NON_SYSTEM_APP_UID, getExsitDate), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetDoNotDisturbDate_00300
 * @tc.name      :
 * @tc.desc      : Get disturbe mode from disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbDate_00300, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> getDate;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetDoNotDisturbDate(TEST_SUBSCRIBE_USER_INIT, getDate),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetHasPoppedDialog_00100
 * @tc.name      :
 * @tc.desc      : Set has popped dialog into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, SetHasPoppedDialog_00100, Function | SmallTest | Level1)
{
    bool hasPopped = false;

    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetHasPoppedDialog(bundleOption_, hasPopped), (int)ERR_OK);

    auto res = NotificationPreferences::GetInstance()->SetHasPoppedDialog(nullptr, hasPopped);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetHasPoppedDialog_00100
 * @tc.name      :
 * @tc.desc      : Get has popped dialog from disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetHasPoppedDialog_00100, Function | SmallTest | Level1)
{
    bool popped = true;

    ASSERT_EQ((int)NotificationPreferences::GetInstance()->SetHasPoppedDialog(bundleOption_, popped), (int)ERR_OK);

    bool hasPopped = false;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetHasPoppedDialog(bundleOption_, hasPopped), (int)ERR_OK);
    EXPECT_TRUE(hasPopped);
}

/**
 * @tc.number    : AddNotificationBundleProperty_00100
 * @tc.name      : AddNotificationBundleProperty
 * @tc.desc      : Add a notification BundleProperty into distrube DB when bundleOption is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationBundleProperty(bundleOption_),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : AddNotificationBundleProperty_00200
 * @tc.name      : AddNotificationBundleProperty
 * @tc.desc      : Add a notification BundleProperty into distrube DB when bundlename is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationBundleProperty(bundleEmptyOption_),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddNotificationBundleProperty_00300
 * @tc.name      : AddNotificationBundleProperty
 * @tc.desc      : Add a notification BundleProperty into distrube DB when bundlename is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00300, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->AddNotificationBundleProperty(nullptr),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00100
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.desc      : Test RemoveNotificationAllSlots function when bundlename is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00100, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationAllSlots(bundleOption_),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00200
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.desc      : Test RemoveNotificationAllSlots function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00200, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationAllSlots(bundleEmptyOption_),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00300
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.desc      : Test RemoveNotificationAllSlots function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00300, Function | SmallTest | Level1)
{
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->RemoveNotificationAllSlots(nullptr),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlotsNumForBundle_00100
 * @tc.name      : GetNotificationSlotsNumForBundle
 * @tc.desc      : Test GetNotificationSlotsNumForBundle function when bundlename is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlotsNumForBundle_00100, Function | SmallTest | Level1)
{
    uint64_t num = 1;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlotsNumForBundle(bundleOption_, num),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : GetNotificationSlotsNumForBundle_00200
 * @tc.name      : GetNotificationSlotsNumForBundle
 * @tc.desc      : Test GetNotificationSlotsNumForBundle function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlotsNumForBundle_00200, Function | SmallTest | Level1)
{
    uint64_t num = 2;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlotsNumForBundle(bundleEmptyOption_, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlotsNumForBundle_00300
 * @tc.name      : GetNotificationSlotsNumForBundle
 * @tc.desc      : Test GetNotificationSlotsNumForBundle function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlotsNumForBundle_00300, Function | SmallTest | Level1)
{
    uint64_t num = 2;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetNotificationSlotsNumForBundle(nullptr, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : CheckSlotForCreateSlot_00100
 * @tc.name      : CheckSlotForCreateSlot
 * @tc.desc      : Test CheckSlotForCreateSlot function when slot is null, return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForCreateSlot_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForCreateSlot(bundleOption_, nullptr, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForCreateSlot_00200
 * @tc.name      : CheckSlotForCreateSlot
 * @tc.desc      : Test CheckSlotForCreateSlot function, return ERR_OK.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForCreateSlot_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForCreateSlot(bundleOption_, slot, info),
        (int)ERR_OK);
}

/**
 * @tc.number    : CheckSlotForRemoveSlot_00100
 * @tc.name      : CheckSlotForRemoveSlot
 * @tc.desc      : Test CheckSlotForRemoveSlot function after add a notification slot,
 * return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForRemoveSlot_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForRemoveSlot(
        bundleOption_, NotificationConstant::SlotType::OTHER, info), (int)ERR_OK);
}

/**
 * @tc.number    : CheckSlotForRemoveSlot_00200
 * @tc.name      : CheckSlotForRemoveSlot
 * @tc.desc      : Test CheckSlotForRemoveSlot function, return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST,
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForRemoveSlot_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForRemoveSlot(
        bundleOption_, NotificationConstant::SlotType::OTHER, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForRemoveSlot_00300
 * @tc.name      : CheckSlotForRemoveSlot
 * @tc.desc      : Test CheckSlotForRemoveSlot function after add a notification slot, return is ERR_OK.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForRemoveSlot_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForRemoveSlot(
        bundleOption_, NotificationConstant::SlotType::CONTENT_INFORMATION, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/*
 * @tc.name: SetSmartReminderEnabled_0100
 * @tc.desc: test SetSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetSmartReminderEnabled_0100, TestSize.Level1)
{
    ErrCode res = NotificationPreferences::GetInstance()->SetSmartReminderEnabled("testDeviceType",
        true);
    ASSERT_EQ(res, ERR_OK);
}

/*
 * @tc.name: SetSmartReminderEnabled_0200
 * @tc.desc: test SetSmartReminderEnabled with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetSmartReminderEnabled_0200, TestSize.Level1)
{
    ErrCode res = NotificationPreferences::GetInstance()->SetSmartReminderEnabled("", true);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsSmartReminderEnabled_0100
 * @tc.desc: test IsSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, IsSmartReminderEnabled_0100, TestSize.Level1)
{
    bool enable = true;
    ErrCode result = NotificationPreferences::GetInstance()->IsSmartReminderEnabled("testDeviceType1",
        enable);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsSmartReminderEnabled_0200
 * @tc.desc: test IsSmartReminderEnabled with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, IsSmartReminderEnabled_0200, TestSize.Level1)
{
    bool enable = true;
    ErrCode result = NotificationPreferences::GetInstance()->IsSmartReminderEnabled("", enable);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00100
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function when slot is null, return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    NotificationPreferencesInfo info;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForUpdateSlot(bundleOption_, nullptr, info),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00200
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function when bundle not existed, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForUpdateSlot(bundleOption_, slot, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00300
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function when slot is different type, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForUpdateSlot(bundleOption_, slot, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : GetAllNotificationEnabledBundles_00100
 * @tc.name      : GetAllNotificationEnabledBundles
 * @tc.desc      : Get all notification enable bundle in DB when db is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED.
 * @tc.require   : issueI92VGR
 */
HWTEST_F(NotificationPreferencesTest, GetAllNotificationEnabledBundles_00100, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> bundleOption;
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->GetAllNotificationEnabledBundles(bundleOption),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00400
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function after add notification slot, return is ERR_OK.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00400, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)NotificationPreferences::GetInstance()->CheckSlotForUpdateSlot(bundleOption_, slot, info),
        (int)ERR_OK);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0100
 * @tc.desc: test SetDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedEnabledByBundle_0100, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode res = NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    ASSERT_EQ(res, ERR_OK);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0200
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedEnabledByBundle_0200, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("", 1));
    std::string deviceType = "testDeviceType";

    ErrCode res = NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(bundleOption,
        deviceType, true);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0100
 * @tc.desc: test IsDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, IsDistributedEnabledByBundle_0100, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = NotificationPreferences::GetInstance()->IsDistributedEnabledByBundle(bundleOption,
        deviceType, enable);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0200
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, IsDistributedEnabledByBundle_0200, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("", 1));
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = NotificationPreferences::GetInstance()->IsDistributedEnabledByBundle(bundleOption,
        deviceType, enable);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0100
 * @tc.desc: test AddDoNotDisturbProfiles id of profile out of range.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, AddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(0);
    profiles.emplace_back(profile);
    auto res = NotificationPreferences::GetInstance()->AddDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0200
 * @tc.desc: test AddDoNotDisturbProfiles when AddDoNotDisturbProfiles of preferncesDB_ return false.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, AddDoNotDisturbProfiles_0200, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    auto res = NotificationPreferences::GetInstance()->AddDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0300
 * @tc.desc: test AddDoNotDisturbProfiles success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, AddDoNotDisturbProfiles_0300, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(1);
    profiles.emplace_back(profile);
    auto res = NotificationPreferences::GetInstance()->AddDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0100
 * @tc.desc: test RemoveDoNotDisturbProfiles id of profile out of range.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, RemoveDoNotDisturbProfiles_0100, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(0);
    profiles.emplace_back(profile);
    auto res = NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0200
 * @tc.desc: test RemoveDoNotDisturbProfiles_0100 when RemoveDoNotDisturbProfiles
 *       of preferncesDB_ return false.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, RemoveDoNotDisturbProfiles_0200, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    auto res = NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0300
 * @tc.desc: test RemoveDoNotDisturbProfiles success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, RemoveDoNotDisturbProfiles_0300, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(1);
    profiles.emplace_back(profile);
    auto res = NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: GetDoNotDisturbProfile_0200
 * @tc.desc: test GetDoNotDisturbProfile when GetDoNotDisturbProfiles of preferncesDB_ return false.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbProfile_0200, TestSize.Level1)
{
    int32_t profileId = 1;
    int32_t userId = 1;
    sptr<NotificationDoNotDisturbProfile> profile;
    auto res = NotificationPreferences::GetInstance()->GetDoNotDisturbProfile(profileId, userId, profile);
    ASSERT_EQ(res, ERR_ANS_NO_PROFILE_TEMPLATE);
}

/**
 * @tc.name: GetDoNotDisturbProfile_0300
 * @tc.desc: test GetDoNotDisturbProfile when GetDoNotDisturbProfiles of preferncesDB_ return true.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbProfile_0300, TestSize.Level1)
{
    int32_t userId = 1;
    int32_t profileId = 1;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profile->SetProfileId(profileId);
    profiles.emplace_back(profile);
    NotificationPreferences::GetInstance()->AddDoNotDisturbProfiles(userId, profiles);
    auto res = NotificationPreferences::GetInstance()->GetDoNotDisturbProfile(profileId, userId, profile);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: GetBundleSoundPermission_0100
 * @tc.desc: test GetBundleSoundPermission.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetBundleSoundPermission_0100, TestSize.Level1)
{
    bool allPackage = true;
    std::set<std::string> bundleNames = {};
    auto res = NotificationPreferences::GetInstance()->GetBundleSoundPermission(allPackage, bundleNames);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: SetDisableNotificationInfo_0100
 * @tc.desc: test SetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDisableNotificationInfo_0100, TestSize.Level1)
{
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    auto res = NotificationPreferences::GetInstance()->SetDisableNotificationInfo(notificationDisable);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: SetDisableNotificationInfo_0200
 * @tc.desc: test SetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDisableNotificationInfo_0200, TestSize.Level1)
{
    auto res = NotificationPreferences::GetInstance()->SetDisableNotificationInfo(nullptr);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDisableNotificationInfo_0100
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDisableNotificationInfo_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    NotificationDisable notificationDisable;
    auto res = notificationPreferences.GetDisableNotificationInfo(notificationDisable);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: GetDisableNotificationInfo_0200
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDisableNotificationInfo_0200, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    notificationPreferences.SetDisableNotificationInfo(notificationDisable);
    NotificationDisable disable;
    auto res = notificationPreferences.GetDisableNotificationInfo(disable);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: SetSubscriberExistFlag_0100
 * @tc.desc: test SetSubscriberExistFlag.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetSubscriberExistFlag_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetSubscriberExistFlag(DEVICE_TYPE_HEADSET, false);
    ASSERT_EQ(ret, ERR_OK);
    bool existFlag = true;
    ret = notificationPreferences.GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, existFlag);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_FALSE(existFlag);
}

/**
 * @tc.name: GetSubscriberExistFlag_0100
 * @tc.desc: test GetSubscriberExistFlag.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetSubscriberExistFlag_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetSubscriberExistFlag(DEVICE_TYPE_HEADSET, true);
    ASSERT_EQ(ret, ERR_OK);
    bool existFlag = false;
    ret = notificationPreferences.GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, existFlag);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(existFlag);
}

/**
 * @tc.name: SetDistributedEnabledForBundle_0100
 * @tc.desc: test SetDistributedEnabledForBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedEnabledForBundle_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    notificationPreferences.SetDistributedEnabledForBundle(bundleInfo);
    notificationPreferences.isCachedMirrorNotificationEnabledStatus_ = true;
    notificationPreferences.mirrorNotificationEnabledStatus_.clear();
    notificationPreferences.SetDistributedEnabledForBundle(bundleInfo);
    EXPECT_EQ(notificationPreferences.mirrorNotificationEnabledStatus_.size(), 0);
    std::string deviceType = "deviceTypeA";
    notificationPreferences.mirrorNotificationEnabledStatus_.push_back(deviceType);
    notificationPreferences.preferncesDB_ = nullptr;
    notificationPreferences.SetDistributedEnabledForBundle(bundleInfo);
    NotificationPreferences otherNotificationPreferences;
    auto ret = otherNotificationPreferences.preferncesDB_->IsDistributedEnabledEmptyForBundle(deviceType, bundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: SetDistributedEnabledForBundle_0200
 * @tc.desc: test SetDistributedEnabledForBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedEnabledForBundle_0200, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("testBundleName");
    bundleInfo.SetBundleUid(1000);
    notificationPreferences.isCachedMirrorNotificationEnabledStatus_ = true;
    std::string deviceType = "deviceTypeC";
    notificationPreferences.mirrorNotificationEnabledStatus_.push_back(deviceType);
    notificationPreferences.SetDistributedEnabledForBundle(bundleInfo);
    bool isDistributedEnabled = false;
    auto ret = notificationPreferences.preferncesDB_->GetDistributedEnabledForBundle(
        deviceType, bundleInfo, isDistributedEnabled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(isDistributedEnabled);
}

/**
 * @tc.number    : UpdateProfilesUtil_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, UpdateProfilesUtil_00100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOne;
    bundleOne.SetBundleName("test1");
    bundleOne.SetUid(100);
    NotificationBundleOption bundleTwo;
    std::vector<NotificationBundleOption> bundleList;
    bundleList.push_back(bundleOne);
    bundleList.push_back(bundleTwo);
    std::vector<NotificationBundleOption> trustList;
    trustList.push_back(bundleOne);
    NotificationPreferences::GetInstance()->UpdateProfilesUtil(trustList, bundleList);
    ASSERT_EQ(bundleList.size(), trustList.size());
}

/**
 * @tc.number    : UpdateDoNotDisturbProfiles_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, UpdateDoNotDisturbProfiles_00100, Function | SmallTest | Level1)
{
    int32_t profileId = 3;
    int32_t userId = 100;
    std::string name = "testProfile";
    std::vector<NotificationBundleOption> bundleList;

    NotificationBundleOption bundleOne;
    bundleOne.SetBundleName("test1");
    bundleOne.SetUid(100);
    bundleList.push_back(bundleOne);

    NotificationCloneBundleInfo cloneBundleInfo;
    NotificationPreferences::GetInstance()->UpdateCloneBundleInfo(
        userId, cloneBundleInfo);

    auto res = NotificationPreferences::GetInstance()->UpdateDoNotDisturbProfiles(
        userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.number    : UpdateDoNotDisturbProfiles_00200
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, UpdateDoNotDisturbProfiles_00200, Function | SmallTest | Level1)
{
    int32_t profileId = 0;
    int32_t userId = 100;
    std::string name = "testProfile";
    std::vector<NotificationBundleOption> bundleList;

    NotificationBundleOption bundleOne;
    bundleOne.SetBundleName("test1");
    bundleOne.SetUid(100);
    bundleList.push_back(bundleOne);

    auto res = NotificationPreferences::GetInstance()->UpdateDoNotDisturbProfiles(
        userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.number    : UpdateDoNotDisturbProfiles_00300
 * @tc.name      : UpdateDoNotDisturbProfiles_00300
 * @tc.desc      : Test UpdateDoNotDisturbProfiles
 */
HWTEST_F(NotificationPreferencesTest, UpdateDoNotDisturbProfiles_00300, Function | SmallTest | Level1)
{
    int32_t profileId = 3;
    int32_t userId = 100;
    std::string name = "testProfile";
    std::vector<NotificationBundleOption> bundleList;

    NotificationCloneBundleInfo cloneBundleInfo;
    NotificationPreferences notificationPreferences;
    notificationPreferences.UpdateCloneBundleInfo(userId, cloneBundleInfo);
    auto res =notificationPreferences.UpdateDoNotDisturbProfiles(userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);

    NotificationBundleOption bundleOne;
    bundleOne.SetBundleName("test1");
    bundleOne.SetUid(100);
    bundleList.push_back(bundleOne);

    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.UpdateDoNotDisturbProfiles(userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);

    notificationPreferences.preferncesDB_ = nullptr;
    res = notificationPreferences.UpdateDoNotDisturbProfiles(userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);
}

 /**
 * @tc.name: UpdateDoNotDisturbProfiles_00400
 * @tc.desc: Test UpdateDoNotDisturbProfile
 * 1. Call the UpdateDoNotDisturbProfiles, assert the result of the method call is ERR_OK
 * 2. Call the UpdateDoNotDisturbProfiles method again with the updated parameters
 * 3. The method of GetDoNotDisturbProfiles will return true
 * 3. Assert that the result is also ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, UpdateDoNotDisturbProfiles_00400, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    int32_t profileId = 0;
    std::string name = "testProfile";
    std::vector<NotificationBundleOption> bundleList;

    NotificationBundleOption bundleOne;
    bundleOne.SetBundleName("test1");
    bundleOne.SetUid(100);
    bundleList.push_back(bundleOne);

    auto res = NotificationPreferences::GetInstance()->UpdateDoNotDisturbProfiles(
        userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_OK);

    name = "testProfile2";
    bundleOne.SetBundleName("test2");
    bundleOne.SetUid(100);
    bundleList.push_back(bundleOne);

    res = NotificationPreferences::GetInstance()->UpdateDoNotDisturbProfiles(
            userId, profileId, name, bundleList);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.number    : GetTemplateSupported_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, GetTemplateSupported_00100, Function | SmallTest | Level1)
{
    bool support = false;
    auto res = NotificationPreferences::GetInstance()->GetTemplateSupported(
        "", support);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetDistributedEnabledBySlot_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedEnabledBySlot_00100, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto res = NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(
        slotType, "test", true);
    ASSERT_EQ(res, ERR_OK);
    
    bool enabled = false;
    res = NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(
        slotType, "test", enabled);
    ASSERT_EQ(res, ERR_OK);
    ASSERT_EQ(enabled, true);
}


/**
 * @tc.number    : GetByteFromDb_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, GetByteFromDb_00100, Function | SmallTest | Level1)
{
    std::vector<uint8_t> value;
    auto res = NotificationPreferences::GetInstance()->GetByteFromDb(
        "test", value, 100);
    ASSERT_NE(res, ERR_OK);
}

/**
 * @tc.number    : DeleteBatchKvFromDb_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, DeleteBatchKvFromDb_00100, Function | SmallTest | Level1)
{
    std::vector<string> keys;
    auto res = NotificationPreferences::GetInstance()->DeleteBatchKvFromDb(
        keys, 100);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.number    : IsAgentRelationship_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, IsAgentRelationship_00100, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    auto res = NotificationPreferences::GetInstance()->IsAgentRelationship(
        "test1", "test2");
    ASSERT_EQ(res, true);
}

/**
 * @tc.number    : GetAdditionalConfig_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, GetAdditionalConfig_00100, Function | SmallTest | Level1)
{
    auto res = NotificationPreferences::GetInstance()->GetAdditionalConfig("test");
    ASSERT_EQ(res, "");
}

/**
 * @tc.number    : DelCloneProfileInfo_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, DelCloneProfileInfo_00100, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbProfile> info(new NotificationDoNotDisturbProfile());
    info->SetProfileId(1);
    info->SetProfileName("TestName");

    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("bundleName");
    bundleOption.SetUid(100);

    std::vector<NotificationBundleOption> trustList;
    trustList.push_back(bundleOption);
    info->SetProfileTrustList(trustList);

    auto res = NotificationPreferences::GetInstance()->DelCloneProfileInfo(
        100, info);
    ASSERT_EQ(res, true);
}

/**
 * @tc.number    : UpdateBatchCloneProfileInfo_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, UpdateBatchCloneProfileInfo_00100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> infos;

    sptr<NotificationDoNotDisturbProfile> info(new NotificationDoNotDisturbProfile());
    info->SetProfileId(1);
    info->SetProfileName("TestName");
    infos.push_back(info);

    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("bundleName");
    bundleOption.SetUid(100);

    std::vector<NotificationBundleOption> trustList;
    trustList.push_back(bundleOption);
    info->SetProfileTrustList(trustList);


    auto res = NotificationPreferences::GetInstance()->UpdateBatchCloneProfileInfo(
        100, infos);
    ASSERT_EQ(res, true);
}

/**
 * @tc.number    : UpdateBatchCloneBundleInfo_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, UpdateBatchCloneBundleInfo_00100, Function | SmallTest | Level1)
{
    std::vector<NotificationCloneBundleInfo> cloneBundleInfos;
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfos.push_back(cloneBundleInfo);
    auto res = NotificationPreferences::GetInstance()->UpdateBatchCloneBundleInfo(
        100, cloneBundleInfos);
    ASSERT_EQ(res, true);

    std::vector<NotificationCloneBundleInfo> cloneBundleInfoRes;
    NotificationPreferences::GetInstance()->GetAllCloneBundleInfo(
        100, cloneBundleInfoRes);
    ASSERT_EQ(cloneBundleInfoRes.size(), cloneBundleInfos.size());
    
    std::vector<sptr<NotificationDoNotDisturbProfile>> profilesInfos;
    NotificationPreferences::GetInstance()->GetAllCloneProfileInfo(
        100, profilesInfos);
    ASSERT_EQ(0, profilesInfos.size());
}

/**
 * @tc.number    : DelCloneBundleInfo_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, DelCloneBundleInfo_00100, Function | SmallTest | Level1)
{
    NotificationCloneBundleInfo cloneBundleInfo;
    auto res = NotificationPreferences::GetInstance()->DelCloneBundleInfo(
        100, cloneBundleInfo);
    ASSERT_EQ(res, true);
}

/**
 * @tc.number    : DelBatchCloneProfileInfo_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, DelBatchCloneProfileInfo_00100, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbProfile> profileInfo(new NotificationDoNotDisturbProfile());

    std::vector<sptr<NotificationDoNotDisturbProfile>> profileInfos;
    profileInfos.push_back(profileInfo);

    auto res = NotificationPreferences::GetInstance()->DelBatchCloneProfileInfo(
        100, profileInfos);
    ASSERT_EQ(res, true);
}

/**
 * @tc.number    : GetAllLiveViewEnabledBundles_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, GetAllLiveViewEnabledBundles_00100, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> bundleOption;
    auto res = NotificationPreferences::GetInstance()->GetAllLiveViewEnabledBundles(
        100, bundleOption);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.number    : GetAllDistribuedEnabledBundles_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, GetAllDistribuedEnabledBundles_00100, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> bundleOption;
    std::string deviceType = "testType";
    auto res = NotificationPreferences::GetInstance()->GetAllDistribuedEnabledBundles(
        100, deviceType, bundleOption);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.number    : SetHashCodeRule_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, SetHashCodeRule_00100, Function | SmallTest | Level1)
{
    auto res = NotificationPreferences::GetInstance()->SetHashCodeRule(
        100, 1);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0400
 * @tc.desc:
 * @tc.type:
 */
HWTEST_F(NotificationPreferencesTest, AddDoNotDisturbProfiles_0400, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;

    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.emplace_back(nullptr);
    int32_t userId = 1;
    auto res = notificationPreferences.AddDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
    profiles.clear();

    sptr<NotificationDoNotDisturbProfile> profile(new (std::nothrow) NotificationDoNotDisturbProfile());
    profile->SetProfileId(1);

    std::vector<NotificationBundleOption> trustList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("test");
    bundle.SetUid(100);
    profile->SetProfileTrustList(trustList);
    profiles.emplace_back(profile);

    notificationPreferences.preferncesDB_ = nullptr;
    res = notificationPreferences.AddDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.name: IsNotificationSlotFlagsExists_0400
 * @tc.desc:
 * @tc.type:
 */
HWTEST_F(NotificationPreferencesTest, IsNotificationSlotFlagsExists_0400, TestSize.Level1)
{
    auto res = NotificationPreferences::GetInstance()->IsNotificationSlotFlagsExists(nullptr);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0400
 * @tc.desc:
 * @tc.type:
 */
HWTEST_F(NotificationPreferencesTest, RemoveDoNotDisturbProfiles_0400, TestSize.Level1)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.emplace_back(nullptr);
    int32_t userId = 1;
    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.RemoveDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
    profiles.clear();

    notificationPreferences.preferncesDB_ = nullptr;
    res = notificationPreferences.RemoveDoNotDisturbProfiles(userId, profiles);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00400
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.require   :
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00400, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);

    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_OK);

    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.RemoveNotificationAllSlots(bundleOption_);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}


/**
 * @tc.number    : AddNotificationBundleProperty_00400
 * @tc.name      : AddNotificationBundleProperty
 * @tc.require   :
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00400, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);

    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_OK);

    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.AddNotificationBundleProperty(bundleOption_);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : SetDoNotDisturbDate_00300
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, SetDoNotDisturbDate_00300, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);

    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.SetDoNotDisturbDate(SYSTEM_APP_UID, date);
    ASSERT_EQ(res, ERR_OK);
    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.SetDoNotDisturbDate(SYSTEM_APP_UID, date);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : UpdateNotificationSlots_00700
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00700, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);

    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_OK);
    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    std::string des("This is a description.");
    slot->SetDescription(des);
    slots.clear();
    slots.push_back(slot);
    res = notificationPreferences.UpdateNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : SetNotificationSlotFlagsForBundle_00100
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationSlotFlagsForBundle_00100, Function | SmallTest | Level1)
{
    auto res = NotificationPreferences::GetInstance()->SetNotificationSlotFlagsForBundle(nullptr, 63);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}


/**
 * @tc.number    : AddNotificationSlots_00700
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00700, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot1);
    slots.push_back(slot2);
    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_OK);
    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : RemoveNotificationSlot_00600
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00600, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);

    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_OK);

    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.RemoveNotificationSlot(bundleOption_,
        NotificationConstant::SlotType::OTHER);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00500
 * @tc.name      :
 * @tc.desc      :
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);

    NotificationPreferences notificationPreferences;
    auto res = notificationPreferences.AddNotificationSlots(bundleOption_, slots);
    ASSERT_EQ(res, ERR_OK);

    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    res = notificationPreferences.RemoveNotificationForBundle(bundleOption_);
    ASSERT_EQ(res, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: NullDeviceTypeTest_001
 * @tc.desc: Test NullDeviceType
 * 1. Declare a string variable deviceType and leave it empty
 * 2. Call the SetDistributedEnabledBySlot/IsDistributedEnabledBySlot/SetSubscriberExistFlag/GetSubscriberExistFlag
 * 3. Assert that res is equal to ERR_ANS_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, NullDeviceTypeTest_001, Function | SmallTest | Level1)
{
    int32_t res;
    bool flag = true;
    std::string deviceType = "";
    NotificationPreferences notificationPreferences;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;

    res = notificationPreferences.SetDistributedEnabledBySlot(slotType, deviceType, flag);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
    res = notificationPreferences.IsDistributedEnabledBySlot(slotType, deviceType, flag);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
    res = notificationPreferences.SetSubscriberExistFlag(deviceType, flag);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
    res = notificationPreferences.GetSubscriberExistFlag(deviceType, flag);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NullPreferncesDBTest_001
 * @tc.desc: Test preferncesDB_
 * 1. Create an instance of NotificationPreferences and set preferncesDB_ to nullptr
 * 2. Call the related methods
 * 3. Assert that the result is as expected
 * @tc.type: FUNC
 */
 HWTEST_F(NotificationPreferencesTest, NullPreferncesDBTest_001, TestSize.Level1)
{
    int32_t res;
    std::string resStr;
    std::string key = "notification";
    std::vector<std::string> keys;
    std::string value = "test";
    std::vector<uint8_t> vecValue;
    std::unordered_map<std::string, std::string> mapValue;
    int32_t userId = 101;
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferncesDB_ = nullptr;
    sptr<NotificationDoNotDisturbProfile> info(new NotificationDoNotDisturbProfile());
    info->SetProfileId(1);
    info->SetProfileName("test");

    res = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.SetByteToDb(key, vecValue, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.GetKvFromDb(key, value, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.GetByteFromDb(key, vecValue, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.GetBatchKvsFromDbContainsKey(key, mapValue, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.GetBatchKvsFromDb(key, mapValue, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.DeleteKvFromDb(key, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.DeleteBatchKvFromDb(keys, userId);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    resStr = notificationPreferences.GetAdditionalConfig(key);
    ASSERT_EQ(resStr.size(), 0);

    res = notificationPreferences.DelCloneProfileInfo(userId, info);
    ASSERT_EQ(res, false);
}
/**
 * @tc.name: NullPreferncesDBTest_002
 * @tc.desc: Test preferncesDB_
 * 1. Create an instance of NotificationPreferences and set preferncesDB_ to nullptr
 * 2. Call the related methods
 * 3. Assert that the result is as expected
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, NullPreferncesDBTest_002, TestSize.Level1)
{
    int32_t res;
    bool flag = true;
    int32_t userId = 101;
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferncesDB_ = nullptr;
    std::vector<NotificationCloneBundleInfo> cloneBundleInfos;
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationDoNotDisturbProfile>> infos;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    cloneBundleInfos.push_back(cloneBundleInfo);
    NotificationDisable disable;
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });

    res = notificationPreferences.UpdateBatchCloneProfileInfo(userId, infos);
    ASSERT_EQ(res, false);

    notificationPreferences.GetAllCloneProfileInfo(userId, infos);
    notificationPreferences.GetAllCloneBundleInfo(userId, cloneBundleInfos);

    res = notificationPreferences.UpdateBatchCloneBundleInfo(userId, cloneBundleInfos);
    ASSERT_EQ(res, false);

    res = notificationPreferences.DelCloneBundleInfo(userId, cloneBundleInfo);
    ASSERT_EQ(res, false);

    res = notificationPreferences.DelBatchCloneProfileInfo(userId, infos);
    ASSERT_EQ(res, false);

    res = notificationPreferences.DelBatchCloneBundleInfo(userId, cloneBundleInfos);
    ASSERT_EQ(res, false);

    res = notificationPreferences.GetDisableNotificationInfo(disable);
    ASSERT_EQ(res, false);

    res = notificationPreferences.SetDisableNotificationInfo(notificationDisable);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.SetSubscriberExistFlag(DEVICE_TYPE_HEADSET, flag);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, flag);
    ASSERT_EQ(res, ERR_ANS_SERVICE_NOT_READY);

    res = notificationPreferences.GetBundleRemoveFlag(bundleOption, slotType, 0);
    ASSERT_EQ(res, true);

    res = notificationPreferences.SetBundleRemoveFlag(bundleOption, slotType, 0);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: GetBundleRemoveFlag_001
 * @tc.desc: Test GetBundleRemoveFlag And SetBundleRemoveFlag
 * 1. Calls SetBundleRemoveFlag with bundleOption, slotType and sourceType, expects the result to be true
 * 2. Calls GetBundleRemoveFlag with the same paras to retrieve the previously set flag, expects the result to be true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetBundleRemoveFlag_001, Function | SmallTest | Level1)
{
    int32_t res;
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;

    res = notificationPreferences.SetBundleRemoveFlag(bundleOption, slotType, 0);
    ASSERT_EQ(res, true);
    
    res = notificationPreferences.GetBundleRemoveFlag(bundleOption, slotType, 0);
    ASSERT_EQ(res, true);
}

/**
 * @tc.name: SetKioskModeStatus_001
 * @tc.desc: Test SetKioskModeStatus
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetKioskModeStatus_001, Function | SmallTest | Level1)
{
    bool isKioskMode = true;
    NotificationPreferences notificationPreferences;
    notificationPreferences.SetKioskModeStatus(isKioskMode);
    ASSERT_EQ(notificationPreferences.isKioskMode_, true);
}

/**
 * @tc.name: IsKioskMode_001
 * @tc.desc: Test IsKioskMode
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, IsKioskMode_001, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.isKioskMode_ = true;
    auto ret = notificationPreferences.IsKioskMode();
    ASSERT_EQ(ret, true);
    notificationPreferences.isKioskMode_ = false;
    ret = notificationPreferences.IsKioskMode();
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_001
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_001, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();
    notificationPreferences.isKioskTrustListUpdate_ = false;
    std::vector<std::string> kioskAppTrustList;
    kioskAppTrustList.push_back("testBundleName1");
    kioskAppTrustList.push_back("testBundleName2");
    notificationPreferences.preferencesInfo_.SetkioskAppTrustList(kioskAppTrustList);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: GetkioskAppTrustList_002
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_002, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_003
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_003, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();

    std::string key = "kiosk_app_trust_list";
    std::string value = "";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_004
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_004, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();

    std::string key = "kiosk_app_trust_list";
    std::string value = "invalid json string";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_005
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_005, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();

    std::string key = "kiosk_app_trust_list";
    std::string value = "null";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_006
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_006, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();

    std::string key = "kiosk_app_trust_list";
    std::string value = "[]";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_007
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_007, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();

    std::string key = "kiosk_app_trust_list";
    std::string value = R"({"key": "value"})";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetkioskAppTrustList_008
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_008, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();

    std::string key = "kiosk_app_trust_list";
    std::string value = R"(["com.example.app1", "com.example.app2", "com.example.app3"])";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: GetkioskAppTrustList_009
 * @tc.desc: Test GetkioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetkioskAppTrustList_009, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();
    notificationPreferences.isKioskTrustListUpdate_ = false;

    std::string key = "kiosk_app_trust_list";
    std::string value = R"(["com.example.app1", "com.example.app2", "com.example.app3"])";
    int32_t userId = -1;
    auto result = notificationPreferences.SetKvToDb(key, value, userId);
    ASSERT_EQ(result, ERR_OK);
    ASSERT_EQ(notificationPreferences.isKioskTrustListUpdate_, true);
    std::vector<std::string> resultList;
    auto ret = notificationPreferences.GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: GetUserDisableNotificationInfo_001
 * @tc.desc: test GetUserDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetUserDisableNotificationInfo_001, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferencesInfo_ = NotificationPreferencesInfo();
    NotificationDisable disable;
    bool ret = NotificationPreferences::GetInstance()->GetUserDisableNotificationInfo(105, disable);
    EXPECT_FALSE(ret);
    notificationPreferences.preferncesDB_ = nullptr;
    ret = notificationPreferences.GetUserDisableNotificationInfo(105, disable);
    EXPECT_FALSE(ret);
}
}  // namespace Notification
}  // namespace OHOS
