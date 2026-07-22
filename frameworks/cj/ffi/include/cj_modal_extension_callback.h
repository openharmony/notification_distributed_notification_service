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

#ifndef CJ_MODAL_EXTENSION_CALLBACK_H
#define CJ_MODAL_EXTENSION_CALLBACK_H

#include <atomic>
#include <memory>
#include <string>

#include "ability_context.h"
#include "ui_content.h"
#include "want.h"

namespace OHOS {
namespace CJSystemapi {
namespace Notification {

class CjModalExtensionCallback {
public:
    CjModalExtensionCallback();
    ~CjModalExtensionCallback();
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const AAFwk::Want& result);
    void OnReceive(const AAFwk::WantParams& receive);
    void OnError(int32_t code, const std::string& name, const std::string& msg);
    void OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void SetSessionId(int32_t sessionId);
    void SetBundleName(const std::string& name);
    void SetAbilityContext(std::shared_ptr<AbilityRuntime::AbilityContext> ctx);
    void ReleaseOrErrorHandle(int32_t code);

private:
    int32_t sessionId_ = 0;
    std::string bundleName_;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext_;
};

} // namespace Notification
} // namespace CJSystemapi
} // namespace OHOS

#endif // CJ_MODAL_EXTENSION_CALLBACK_H
