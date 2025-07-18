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

#ifndef MOCK_DISTRIBUTED_DEVICE_MANAGER_IMPL_H
#define MOCK_DISTRIBUTED_DEVICE_MANAGER_IMPL_H

#include "device_manager_impl.h"

namespace OHOS {
namespace Notification {

class DeviceTrigger {
public:
    static void MockConfigScene(int32_t scene);
    static void MockInitDeviceManager(bool mock);
    static void MockGetTrustedDeviceList(bool mock);
    static void MockRegisterDevStateCallback(bool mock);
    static void MockTransDeviceIdToUdid(bool mock);
    static void TriggerOnRemoteDied();
    static void TriggerDeviceOnline();
    static void TriggerDeviceOffline();
    static void TriggerDeviceChanged();
    static void TriggerDeviceReady();
};

class DeviceCheck {
public:
    static bool CheckDeviceOnline();
    static void ResetDeviceData();
    static std::string GetDeviceNetworkId(std::string deviceId);
};

} // namespace Notification
} // namespace OHOS

#endif // MOCK_DISTRIBUTED_DEVICE_MANAGER_IMPL_H
