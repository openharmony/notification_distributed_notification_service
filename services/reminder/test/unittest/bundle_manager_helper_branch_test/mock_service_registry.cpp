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

#include "iservice_registry.h"

#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "mock_service_registry.h"

namespace {
    bool g_mockGetSystemAbilityManagerRet = true;
}

void MockServiceRegistry::MockGetSystemAbilityManager(bool mockRet)
{
    g_mockGetSystemAbilityManagerRet = mockRet;
}

namespace OHOS {
sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    if (false == g_mockGetSystemAbilityManagerRet) {
        if (systemAbilityManager_ != nullptr) {
            return systemAbilityManager_;
        }
        sptr<IRemoteObject> registryObject = IPCSkeleton::GetContextObject();
        systemAbilityManager_ = iface_cast<ISystemAbilityManager>(registryObject);
        return systemAbilityManager_;
    }
    return nullptr;
}
} // namespace OHOS
