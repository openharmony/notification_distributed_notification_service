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

#ifndef OHOS_NOTIFICATION_MOCK_ANS_NOTIFICATION_H
#define OHOS_NOTIFICATION_MOCK_ANS_NOTIFICATION_H

#include "gmock/gmock.h"
#include "ans_notification.h"

namespace OHOS {
namespace Notification {
class MockAnsNotification : public AnsNotification {
public:
    MOCK_METHOD0(GetAnsManagerProxy, sptr<IAnsManager>());
};
}  // namespace Notification
}  // namespace OHOS

#endif  // OHOS_NOTIFICATION_MOCK_ANS_NOTIFICATION_H
