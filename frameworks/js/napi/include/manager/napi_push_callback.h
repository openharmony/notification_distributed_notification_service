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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_H

#include <chrono>
#include <iremote_object.h>

#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
#include "parcel.h"
#include "push_callback_stub.h"
#include "want.h"

class NativeReference;

namespace OHOS {
namespace Notification {
/**
 * @class JSPushCallBack
 */
class JSPushCallBack : public PushCallBackStub {
public:
    JSPushCallBack(napi_env env);
    virtual ~JSPushCallBack();
    int32_t OnCheckNotification(const std::string &notificationData);
    void SetJsPushCallBackObject(napi_value pushCallBackObject);
    bool IsEqualPushCallBackObject(napi_value pushCallBackObject);
    int32_t HandleCheckPromise(napi_value funcResult);
    static napi_value CheckPromiseCallback(napi_env env, napi_callback_info info);

private:
    static bool ConvertFunctionResult(napi_env env, napi_value funcResult);
    void SetJsPropertyString(std::string key, std::string value, napi_value& jsResult);
    void SetJsPropertyInt32(std::string key, int32_t value, napi_value& jsResult);
    void SetJsPropertyWantParams(std::string key, std::shared_ptr<AAFwk::WantParams> wantParams, napi_value& jsResult);
    napi_env env_ = nullptr;
    napi_ref pushCallBackObject_ = nullptr;
    std::mutex mutexlock;
    static int32_t checkResult_;
};
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_H
