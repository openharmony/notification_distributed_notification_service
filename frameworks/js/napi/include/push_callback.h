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

#include <iremote_object.h>

#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
#include "parcel.h"
#include "push_callback_stub.h"

class NativeReference;
class NativeValue;

namespace OHOS {
namespace Notification {
/**
 * @class JSPushCallBack
 */
class JSPushCallBack : public PushCallBackStub {
public:
    JSPushCallBack(NativeEngine &engine);
    ~JSPushCallBack();
    bool OnCheckNotification(const std::string &notificationData);
    void SetJsPushCallBackObject(NativeValue *pushCallBackObject);

private:
    bool ConvertFunctionResult(NativeValue *funcResult);

    NativeEngine &engine_;
    std::unique_ptr<NativeReference> pushCallBackObject_;
};
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_H
