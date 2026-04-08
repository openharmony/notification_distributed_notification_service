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
#include "notification_voice_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationVoiceContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetTextContent_00001
 * @tc.desc: Test SetTextContent parameters.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, SetTextContent_00001, Level1)
{
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    std::string textContent = "Hello, this is a voice content";
    voiceContent->SetTextContent(textContent);
    EXPECT_EQ(voiceContent->GetTextContent(), textContent);
}

/**
 * @tc.name: SetTextContent_00002
 * @tc.desc: Test SetTextContent with empty string.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, SetTextContent_00002, Level1)
{
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    std::string textContent = "";
    voiceContent->SetTextContent(textContent);
    EXPECT_EQ(voiceContent->GetTextContent(), textContent);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Dump_00001, Level1)
{
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    voiceContent->SetTextContent("Test voice content");
    std::string ret = "NotificationVoiceContent{ textContent = Test voice content }";
    EXPECT_EQ(voiceContent->Dump(), ret);
}

/**
 * @tc.name: Dump_00002
 * @tc.desc: Test Dump with empty content.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Dump_00002, Level1)
{
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    std::string ret = "NotificationVoiceContent{ textContent =  }";
    EXPECT_EQ(voiceContent->Dump(), ret);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshallingaring parameters.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Marshalling_00001, Level1)
{
    Parcel parcel;
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    voiceContent->SetTextContent("Test voice content");
    EXPECT_EQ(voiceContent->Marshalling(parcel), true);
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshallingaring with empty content.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Marshalling_00002, Level1)
{
    Parcel parcel;
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    EXPECT_EQ(voiceContent->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshallingaring with null parcel.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Unmarshalling_00001, Level1)
{
    Parcel parcel;
    auto result = NotificationVoiceContent::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshallingaring with data.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Unmarshalling_00002, Level1)
{
    Parcel parcel;
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    voiceContent->SetTextContent("Test voice content");
    voiceContent->Marshalling(parcel);
    
    auto result = NotificationVoiceContent::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetTextContent(), "Test voice content");
}

/**
 * @tc.name: Unmarshalling_00003
 * @tc.desc: Test Unmarshallingaring with empty content.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, Unmarshalling_00003, Level1)
{
    Parcel parcel;
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    voiceContent->SetTextContent("");
    voiceContent->Marshalling(parcel);
    
    auto result = NotificationVoiceContent::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetTextContent(), "");
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel with data.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, ReadFromParcel_00001, Level1)
{
    Parcel parcel;
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    voiceContent->SetTextContent("Test voice content");
    voiceContent->Marshalling(parcel);
    
    auto result = std::make_shared<NotificationVoiceContent>();
    EXPECT_EQ(result->ReadFromParcel(parcel), true);
    EXPECT_EQ(result->GetTextContent(), "Test voice content");
}

/**
 * @tc.name: ReadFromParcel_00002
 * @tc.desc: Test ReadFromParcel with empty content.
 * @tc.type: FUNC
 * @tc.require: AR000H0PCK
 */
HWTEST_F(NotificationVoiceContentTest, ReadFromParcel_00002, Level1)
{
    Parcel parcel;
    auto voiceContent = std::make_shared<NotificationVoiceContent>();
    voiceContent->SetTextContent("");
    voiceContent->Marshalling(parcel);
    
    auto result = std::make_shared<NotificationVoiceContent>();
    EXPECT_EQ(result->ReadFromParcel(parcel), true);
    EXPECT_EQ(result->GetTextContent(), "");
}

}  // namespace Notification
}  // namespace OHOS
