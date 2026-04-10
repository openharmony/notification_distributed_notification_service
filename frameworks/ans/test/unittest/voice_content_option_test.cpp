/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "voice_content_option.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class VoiceContentOptionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(VoiceContentOptionTest, Constructor_00001, Function | SmallTest | Level1)
{
    VoiceContentOption option;
    EXPECT_EQ(option.GetEnabled(), false);
}

HWTEST_F(VoiceContentOptionTest, Constructor_00002, Function | SmallTest | Level1)
{
    VoiceContentOption option(true);
    EXPECT_EQ(option.GetEnabled(), true);
}

HWTEST_F(VoiceContentOptionTest, Constructor_00003, Function | SmallTest | Level1)
{
    VoiceContentOption option1(true);
    VoiceContentOption option2(option1);
    EXPECT_EQ(option2.GetEnabled(), true);
}

HWTEST_F(VoiceContentOptionTest, Constructor_00004, Function | SmallTest | Level1)
{
    VoiceContentOption option1(false);
    VoiceContentOption option2(option1);
    EXPECT_EQ(option2.GetEnabled(), false);
}

HWTEST_F(VoiceContentOptionTest, SetEnabled_00001, Function | SmallTest | Level1)
{
    VoiceContentOption option;
    option.SetEnabled(true);
    EXPECT_EQ(option.GetEnabled(), true);
}

HWTEST_F(VoiceContentOptionTest, SetEnabled_00002, Function | SmallTest | Level1)
{
    VoiceContentOption option(true);
    option.SetEnabled(false);
    EXPECT_EQ(option.GetEnabled(), false);
}

HWTEST_F(VoiceContentOptionTest, SetEnabled_00003, Function | SmallTest | Level1)
{
    VoiceContentOption option;
    option.SetEnabled(true);
    option.SetEnabled(false);
    option.SetEnabled(true);
    EXPECT_EQ(option.GetEnabled(), true);
}

HWTEST_F(VoiceContentOptionTest, Marshalling_00001, Function | SmallTest | Level1)
{
    VoiceContentOption option(true);
    Parcel parcel;
    EXPECT_EQ(option.Marshalling(parcel), true);
}

HWTEST_F(VoiceContentOptionTest, Marshalling_00002, Function | SmallTest | Level1)
{
    VoiceContentOption option(false);
    Parcel parcel;
    EXPECT_EQ(option.Marshalling(parcel), true);
}

HWTEST_F(VoiceContentOptionTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    VoiceContentOption option(true);
    Parcel parcel;
    option.Marshalling(parcel);
    parcel.RewindRead(0);
    VoiceContentOption *result = VoiceContentOption::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetEnabled(), true);
    delete result;
}

HWTEST_F(VoiceContentOptionTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    VoiceContentOption option(false);
    Parcel parcel;
    option.Marshalling(parcel);
    parcel.RewindRead(0);
    VoiceContentOption *result = VoiceContentOption::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetEnabled(), false);
    delete result;
}

HWTEST_F(VoiceContentOptionTest, CopyAssignment_00001, Function | SmallTest | Level1)
{
    VoiceContentOption option1(true);
    VoiceContentOption option2;
    option2 = option1;
    EXPECT_EQ(option2.GetEnabled(), true);
}

HWTEST_F(VoiceContentOptionTest, CopyAssignment_00002, Function | SmallTest | Level1)
{
    VoiceContentOption option1(false);
    VoiceContentOption option2(true);
    option2 = option1;
    EXPECT_EQ(option2.GetEnabled(), false);
}
}  // namespace Notification
}  // namespace OHOS
