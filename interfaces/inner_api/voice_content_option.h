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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_VOICE_CONTENT_OPTION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_VOICE_CONTENT_OPTION_H

#include "parcel.h"

namespace OHOS {
namespace Notification {
class VoiceContentOption : public Parcelable {
public:
    VoiceContentOption();

    explicit VoiceContentOption(bool enabled);

    VoiceContentOption(const VoiceContentOption &option);

    ~VoiceContentOption();

    void SetEnabled(bool enabled);

    bool GetEnabled() const;

    bool Marshalling(Parcel &parcel) const override;

    static VoiceContentOption *Unmarshalling(Parcel &parcel);

    VoiceContentOption& operator=(const VoiceContentOption &option);

private:
    bool ReadFromParcel(Parcel &parcel);

    bool enabled_ = false;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_VOICE_CONTENT_OPTION_H
