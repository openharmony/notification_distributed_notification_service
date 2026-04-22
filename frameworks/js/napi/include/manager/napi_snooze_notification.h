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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SNOOZE_NOTIFICATION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SNOOZE_NOTIFICATION_H

#include <string>
#include "common.h"
#include "notification_bundle_option.h"
#include "notification_statistics.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct AsyncCallbackInfoSnooze {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::string hashCode = "";
    long delayTime = 0;
    CallbackPromiseInfo info;
};

napi_value NapiSnoozeNotification(napi_env env, napi_callback_info info);
}
}

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SNOOZE_NOTIFICATION_H