/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "advanced_notification_service_ability.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
const int ANS_CLONE_ERROR = -1;
class AdvancedNotificationServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00100
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0100
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility(systemAbilityId, runOnCreate);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00200
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0200
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00200, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00300
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0300
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStop();
    test.OnStart();
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00400
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0400
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00400, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string extension = "backup";
    MessageParcel data;
    MessageParcel reply;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    ErrCode ret = test.OnExtension(extension, data, reply);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00500
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0500
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00500, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string extension = "restore";
    MessageParcel data;
    MessageParcel reply;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    ErrCode ret = test.OnExtension(extension, data, reply);
    EXPECT_EQ(ret, (int)ANS_CLONE_ERROR);
}
}  // namespace Notification
}  // namespace OHOS
