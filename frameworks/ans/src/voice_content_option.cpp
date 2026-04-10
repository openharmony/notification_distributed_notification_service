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

#include "voice_content_option.h"

#include <new>

#include "ans_log_wrapper.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
VoiceContentOption::VoiceContentOption()
{}

VoiceContentOption::VoiceContentOption(bool enabled) : enabled_(enabled)
{}

VoiceContentOption::VoiceContentOption(const VoiceContentOption &option) : enabled_(option.enabled_)
{}

VoiceContentOption::~VoiceContentOption()
{}

void VoiceContentOption::SetEnabled(bool enabled)
{
    enabled_ = enabled;
}

bool VoiceContentOption::GetEnabled() const
{
    return enabled_;
}

bool VoiceContentOption::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(enabled_)) {
        ANS_LOGE("Failed to write enabled_");
        return false;
    }
    return true;
}

VoiceContentOption *VoiceContentOption::Unmarshalling(Parcel &parcel)
{
    VoiceContentOption *option = new (std::nothrow) VoiceContentOption();
    if (option && !option->ReadFromParcel(parcel)) {
        delete option;
        option = nullptr;
    }
    return option;
}

bool VoiceContentOption::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadBool(enabled_)) {
        ANS_LOGE("Failed to read enabled_");
        return false;
    }
    return true;
}

VoiceContentOption& VoiceContentOption::operator=(const VoiceContentOption &option)
{
    if (this != &option) {
        enabled_ = option.enabled_;
    }
    return *this;
}
}  // namespace Notification
}  // namespace OHOS
