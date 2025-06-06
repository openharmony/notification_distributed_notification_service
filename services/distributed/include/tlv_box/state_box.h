/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_STATUS_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_STATUS_BOX_H

#include <string>
#include "tlv_box.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {
class NotifticationStateBox : public BoxBase {
public:
    NotifticationStateBox();
    NotifticationStateBox(std::shared_ptr<TlvBox> box);
#ifdef DISTRIBUTED_FEATURE_MASTER
    bool GetDeviceType(std::string& deviceType);
    bool GetDeviceId(std::string& deviceId);
    bool GetState(int32_t& state);
    bool GetLiveViewEnable(bool& enable);
    bool GetNotificationEnable(bool& enable);
#else
    bool SetDeviceType(const std::string& deviceType);
    bool SetDeviceId(const std::string& deviceId);
    bool SetState(int32_t state);
    bool SetLiveViewEnable(bool enable);
    bool SetNotificationEnable(bool enable);
#endif
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_STATUS_BOX_H
