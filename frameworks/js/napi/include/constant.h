/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_CONSTANT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_CONSTANT_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
napi_value RemoveReasonInit(napi_env env, napi_value exports);
napi_value SlotTypeInit(napi_env env, napi_value exports);
napi_value SlotLevelInit(napi_env env, napi_value exports);
napi_value SemanticActionButtonInit(napi_env env, napi_value exports);
napi_value InputsSourceInit(napi_env env, napi_value exports);
napi_value DoNotDisturbMode(napi_env env, napi_value exports);
napi_value InputEditTypeInit(napi_env env, napi_value exports);
napi_value ContentTypeInit(napi_env env, napi_value exports);
napi_value DoNotDisturbTypeInit(napi_env env, napi_value exports);
napi_value DeviceRemindTypeInit(napi_env env, napi_value exports);
napi_value ConstantInit(napi_env env, napi_value exports);
napi_value LiveViewStatusInit(napi_env env, napi_value exports);
napi_value SwitchStateInit(napi_env env, napi_value exports);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_CONSTANT_H
