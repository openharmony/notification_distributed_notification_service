/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "push_callback.h"

#include "ans_log_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace Notification {
constexpr size_t ARGC_ONE = 1;

JSPushCallBack::JSPushCallBack(NativeEngine &engine) : engine_(engine) {}

JSPushCallBack::~JSPushCallBack() {}

void JSPushCallBack::SetJsPushCallBackObject(NativeValue *pushCallBackObject)
{
    pushCallBackObject_ = std::unique_ptr<NativeReference>(engine_.CreateReference(pushCallBackObject, 1));
}

bool JSPushCallBack::OnCheckNotification(const std::string &notificationData)
{
    AbilityRuntime::HandleEscape handleEscape(engine_);
    wptr<JSPushCallBack> pushCallBack = this;
    sptr<JSPushCallBack> pushCallBackSptr = pushCallBack.promote();
    if (pushCallBackSptr == nullptr) {
        ANS_LOGE("pushCallBackSptr nullptr");
        return false;
    }

    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return false;
    }

    NativeValue *value = pushCallBackObject_->Get();
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return false;
    }

    NativeValue *jsdata = AbilityRuntime::CreateJsValue(engine_, notificationData);
    NativeValue *funcResult;
    NativeValue *argv[] = { jsdata };
    funcResult = handleEscape.Escape(engine_.CallFunction(value, value, argv, ARGC_ONE));

    return ConvertFunctionResult(funcResult);
}

bool JSPushCallBack::ConvertFunctionResult(NativeValue *funcResult)
{
    if (funcResult == nullptr || funcResult->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        ANS_LOGE("funcResult TypeOf error.");
        return false;
    }

    NativeObject *obj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(funcResult);
    if (obj == nullptr) {
        ANS_LOGE("obj is nullptr.");
        return false;
    }

    auto codeJsvalue = obj->GetProperty("code");
    if (codeJsvalue == nullptr || codeJsvalue->TypeOf() != NativeValueType::NATIVE_NUMBER) {
        ANS_LOGE("GetProperty code failed.");
        return false;
    }

    uint32_t code = 1;
    if (!AbilityRuntime::ConvertFromJsValue(engine_, codeJsvalue, code)) {
        ANS_LOGE("Parse code failed.");
        return false;
    }

    auto messageJsvalue = obj->GetProperty("message");
    if (messageJsvalue == nullptr || messageJsvalue->TypeOf() != NativeValueType::NATIVE_STRING) {
        ANS_LOGE("GetProperty message failed.");
    }

    std::string message;
    if (!AbilityRuntime::ConvertFromJsValue(engine_, messageJsvalue, message)) {
        ANS_LOGE("Parse message failed.");
    }

    ANS_LOGI("code : %{public}d ,message : %{public}s", code, message.c_str());

    return code == 0 ? true : false;
}
} // namespace Notification
} // namespace OHOS