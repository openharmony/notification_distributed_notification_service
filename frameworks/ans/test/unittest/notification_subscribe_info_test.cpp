/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <string>

#define private public
#define protected public
#include "notification_subscribe_info.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSubscribeInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AddAppName_00001
 * @tc.desc: Test AddAppName parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, AddAppName_00001, Function | SmallTest | Level1)
{
    std::string appName = "AppName";
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->AddAppName(appName);
    std::vector<std::string> result = rrc->GetAppNames();
    EXPECT_EQ(result.size(), 1);
}

/**
 * @tc.name: AddAppNames_00001
 * @tc.desc: Test AddAppNames parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, AddAppNames_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> appNames;
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->AddAppNames(appNames);
    std::vector<std::string> result = rrc->GetAppNames();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: AddAppUserId_00001
 * @tc.desc: Test AddAppUserId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, AddAppUserId_00001, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->AddAppUserId(userId);
    EXPECT_EQ(rrc->GetAppUserId(), userId);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    NotificationSubscribeInfo subscribeInfo;
    std::shared_ptr<NotificationSubscribeInfo> result =
    std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    result->Marshalling(parcel);

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->Marshalling(parcel);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), true);
}

/**
 * @tc.name: AddDeviceType_00001
 * @tc.desc: Test AddDeviceType.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, AddDeviceType_00001, Function | SmallTest | Level1)
{
    std::string deviceType = "test";
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->AddDeviceType(deviceType);
    EXPECT_EQ(rrc->GetDeviceType(), deviceType);
}

HWTEST_F(NotificationSubscribeInfoTest, AddSubscribedFlags_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->SetSubscribedFlags(0xfff);
    EXPECT_EQ(rrc->GetSubscribedFlags(), 0xfff);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string deviceType = "test";
    std::string appName = "AppName";
    int32_t userId = 100;
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->AddDeviceType(deviceType);
    rrc->AddAppName(appName);
    rrc->AddAppUserId(userId);
    std::string res = "NotificationSubscribeInfo{ "
            "appNames = [" + appName + ", ]" +
            "deviceType = " + deviceType +
            "userId = " + std::to_string(userId) +
            "slotTypes = []needNotify = 0filterType = 0needResponse = 0isSubscribeSelf = 0voiceContentOption = null"
            " }";
    EXPECT_EQ(res, rrc->Dump());
}

/**
 * @tc.name: SetVoiceContentOption_00001
 * @tc.desc: Test SetVoiceContentOption with nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, SetVoiceContentOption_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->SetVoiceContentOption(nullptr);
    EXPECT_EQ(rrc->GetVoiceContentOption(), nullptr);
}

/**
 * @tc.name: SetVoiceContentOption_00002
 * @tc.desc: Test SetVoiceContentOption with valid object.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, SetVoiceContentOption_00002, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(true);
    rrc->SetVoiceContentOption(option);
    ASSERT_NE(rrc->GetVoiceContentOption(), nullptr);
    EXPECT_EQ(rrc->GetVoiceContentOption()->GetEnabled(), true);
}

/**
 * @tc.name: SetVoiceContentOption_00003
 * @tc.desc: Test SetVoiceContentOption with disabled option.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, SetVoiceContentOption_00003, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(false);
    rrc->SetVoiceContentOption(option);
    ASSERT_NE(rrc->GetVoiceContentOption(), nullptr);
    EXPECT_EQ(rrc->GetVoiceContentOption()->GetEnabled(), false);
}

/**
 * @tc.name: Marshalling_VoiceContentOption_00001
 * @tc.desc: Test Marshalling with VoiceContentOption.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Marshalling_VoiceContentOption_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(true);
    rrc->SetVoiceContentOption(option);
    Parcel parcel;
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_VoiceContentOption_00001
 * @tc.desc: Test Unmarshalling with VoiceContentOption.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Unmarshalling_VoiceContentOption_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(true);
    rrc->SetVoiceContentOption(option);
    Parcel parcel;
    rrc->Marshalling(parcel);
    parcel.RewindRead(0);
    NotificationSubscribeInfo *result = NotificationSubscribeInfo::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    ASSERT_NE(result->GetVoiceContentOption(), nullptr);
    EXPECT_EQ(result->GetVoiceContentOption()->GetEnabled(), true);
    delete result;
}

/**
 * @tc.name: Unmarshalling_VoiceContentOption_00002
 * @tc.desc: Test Unmarshalling without VoiceContentOption.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Unmarshalling_VoiceContentOption_00002, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    Parcel parcel;
    rrc->Marshalling(parcel);
    parcel.RewindRead(0);
    NotificationSubscribeInfo *result = NotificationSubscribeInfo::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetVoiceContentOption(), nullptr);
    delete result;
}

/**
 * @tc.name: CopyConstructor_VoiceContentOption_00001
 * @tc.desc: Test copy constructor with VoiceContentOption.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, CopyConstructor_VoiceContentOption_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(true);
    rrc->SetVoiceContentOption(option);
    NotificationSubscribeInfo copyInfo(*rrc);
    ASSERT_NE(copyInfo.GetVoiceContentOption(), nullptr);
    EXPECT_EQ(copyInfo.GetVoiceContentOption()->GetEnabled(), true);
}

/**
 * @tc.name: Dump_VoiceContentOption_00001
 * @tc.desc: Test Dump with VoiceContentOption enabled.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Dump_VoiceContentOption_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(true);
    rrc->SetVoiceContentOption(option);
    std::string dump = rrc->Dump();
    EXPECT_NE(dump.find("voiceContentOption = enabled"), std::string::npos);
}

/**
 * @tc.name: Dump_VoiceContentOption_00002
 * @tc.desc: Test Dump with VoiceContentOption disabled.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, Dump_VoiceContentOption_00002, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(false);
    rrc->SetVoiceContentOption(option);
    std::string dump = rrc->Dump();
    EXPECT_NE(dump.find("voiceContentOption = disabled"), std::string::npos);
}

/**
 * @tc.name: SubscribedFlags_VoiceContentOption_00001
 * @tc.desc: Test that VoiceContentOption enabled sets SUBSCRIBE_ON_VOICE_CONTENT flag.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, SubscribedFlags_VoiceContentOption_00001, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    sptr<VoiceContentOption> option = new VoiceContentOption(true);
    rrc->SetVoiceContentOption(option);
    uint32_t flags = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT;
    EXPECT_EQ(rrc->GetSubscribedFlags() & flags, 0);
}

/**
 * @tc.name: SubscribedFlags_VoiceContentOption_00003
 * @tc.desc: Test that nullptr VoiceContentOption does not set SUBSCRIBE_ON_VOICE_CONTENT flag.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscribeInfoTest, SubscribedFlags_VoiceContentOption_00003, Function | SmallTest | Level1)
{
    NotificationSubscribeInfo subscribeInfo;
    auto rrc = std::make_shared<NotificationSubscribeInfo>(subscribeInfo);
    rrc->SetVoiceContentOption(nullptr);
    uint32_t flags = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT;
    EXPECT_EQ(rrc->GetSubscribedFlags() & flags, 0);
}
}
}
