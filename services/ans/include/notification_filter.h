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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_SERVICES_ANS_INCLUDE_NOTIFICATION_FILTER_H
#define BASE_NOTIFICATION_ANS_STANDARD_SERVICES_ANS_INCLUDE_NOTIFICATION_FILTER_H

#include <memory>

#include "errors.h"

#include "notification_record.h"

namespace OHOS {
namespace Notification {
class INotificationFilter {
public:
    INotificationFilter() {};
    virtual ~INotificationFilter() {};

    virtual void OnStart() = 0;
    virtual void OnStop() = 0;

    virtual ErrCode OnPublish(const std::shared_ptr<NotificationRecord> &record) = 0;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_SERVICES_ANS_INCLUDE_NOTIFICATION_FILTER_H