/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_COMMON_NOTIFICATION_PUBLISH_PROCESS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_COMMON_NOTIFICATION_PUBLISH_PROCESS_H

#include "base_publish_process.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
class CommonNotificationPublishProcess final : public BasePublishProcess {
public:
    static std::shared_ptr<CommonNotificationPublishProcess> GetInstance();
    ErrCode PublishNotificationByApp(const sptr<NotificationRequest> &request) override;

private:
    static std::shared_ptr<CommonNotificationPublishProcess> instance_;
    static ffrt::mutex instanceMutex_;
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_COMMON_NOTIFICATION_PUBLISH_PROCESS_H
