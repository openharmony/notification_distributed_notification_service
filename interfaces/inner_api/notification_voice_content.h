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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_VOICE_CONTENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_VOICE_CONTENT_H

#include "parcel.h"

namespace OHOS {
namespace Notification {

class NotificationVoiceContent : public Parcelable {
public:
    NotificationVoiceContent() = default;

    ~NotificationVoiceContent() = default;

    NotificationVoiceContent(const NotificationVoiceContent& other);

    void SetTextContent(const std::string &textContent);

    std::string GetTextContent() const;

    std::string Dump();

    virtual bool Marshalling(Parcel &parcel) const override;

    static NotificationVoiceContent *Unmarshalling(Parcel &parcel);

protected:
    bool ReadFromParcel(Parcel &parcel);

private:
    std::string textContent_ {};
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_VOICE_CONTENT_H
