/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"

#define private public
#define protected public
#include "notification_clone_priority_service.h"
#undef private
#undef protected
#include "advanced_notification_service.h"
#include "notification_clone_util.h"
#include "notification_preferences.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
// Test suite class
class NotificationClonePriorityTest : public ::testing::Test {
protected:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        int32_t userId = NotificationCloneUtil::GetActiveUserId();
        NotificationClonePriority::GetInstance()->OnRestoreEnd(userId);
    }
    void TearDown() {}
};

/**
 * @tc.name: OnBackUp_00001
 * @tc.desc: Test clone OnBackUp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnBackUp_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bundleOption, "test1\\ntest2\\ntest3");
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bundleOption, 0);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->OnBackup(jsonObject), ERR_OK);
}

/**
 * @tc.name: OnRestoreStart_00001
 * @tc.desc: Test clone OnRestoreStart success.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreStart_00001, Function | SmallTest | Level1)
{
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationClonePriority::GetInstance()->OnRestoreStart("bundleName", 0, userId, 1000);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->fromUnSupportPriority_, true);
}

/**
 * @tc.name: OnRestoreStart_00002
 * @tc.desc: Test clone OnRestoreStart after OnRestore.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreStart_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationClonePriorityInfo priorityInfo;
    priorityInfo.bundleName_ = "bundleName";
    priorityInfo.appIndex_ = 0;
    priorityInfo.enableStatus_ = 30;
    priorityInfo.clonePriorityType_ = NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_STRATEGY_FOR_BUNDLE;
    cloneInfos.push_back(priorityInfo);
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
    }
    std::set<std::string> systemApps;
    NotificationClonePriority::GetInstance()->restoreVer_ = 2;
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.size(), 1);
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationClonePriority::GetInstance()->OnRestoreStart("bundleName", 0, userId, 1000);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreEnd_001
 * @tc.desc: Test that clear priority info.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreEnd_001, Function | SmallTest | Level1)
{
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationClonePriority::GetInstance()->OnRestoreEnd(userId);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.empty(), true);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->fromUnSupportPriority_, true);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->restoreVer_, 1);
}

/**
 * @tc.name: OnRestoreV1_00001
 * @tc.desc: Test clone OnRestoreV1 with systemApp priorityInfo success.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreV1_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName2", 1000);
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationClonePriorityInfo priorityInfo;
    priorityInfo.bundleName_ = "bundleName2";
    priorityInfo.appIndex_ = 0;
    priorityInfo.enableStatus_ = 2;
    priorityInfo.clonePriorityType_ = NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE;
    cloneInfos.push_back(priorityInfo);
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
    }
    std::set<std::string> systemApps = {"bundleName2"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreV2_00001
 * @tc.desc: Test clone OnRestoreV2 with systemApp priorityInfo success.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreV2_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName3", 1000);
    std::map<sptr<NotificationBundleOption>, bool> priorityEnableMap;
    priorityEnableMap.emplace(std::move(bundleOption), true);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundles(priorityEnableMap);
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationClonePriorityInfo priorityInfo1;
    priorityInfo1.bundleName_ = "bundleName3";
    priorityInfo1.appIndex_ = 0;
    priorityInfo1.enableStatus_ = 1;
    priorityInfo1.clonePriorityType_ =
        NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_INTELLIGENT_ENABLE;
    cloneInfos.emplace_back(priorityInfo1);
    NotificationClonePriorityInfo priorityInfo2;
    priorityInfo2.bundleName_ = "bundleName3";
    priorityInfo2.appIndex_ = 0;
    priorityInfo2.enableStatus_ = 1;
    priorityInfo2.clonePriorityType_ =
        NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE_V2;
    cloneInfos.emplace_back(priorityInfo2);
    NotificationClonePriorityInfo priorityInfo3;
    priorityInfo3.bundleName_ = "bundleName3";
    priorityInfo3.appIndex_ = 0;
    priorityInfo3.enableStatus_ = 30;
    priorityInfo3.clonePriorityType_ =
        NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_STRATEGY_FOR_BUNDLE;
    cloneInfos.emplace_back(priorityInfo3);
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
    }
    std::set<std::string> systemApps = {"bundleName3"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->fromUnSupportPriority_, false);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.empty(), true);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->restoreVer_, 2);
}

/**
 * @tc.name: OnRestoreV1_00002
 * @tc.desc: Test clone OnRestore when old device jsonObject invalid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestore_00003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundle;
    nlohmann::json jsonNode;
    cloneBundle.ToJson(jsonNode);
    jsonObject.emplace_back(jsonNode);
    std::set<std::string> systemApps = {"bundleName"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->fromUnSupportPriority_, true);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.empty(), true);
}
}
}