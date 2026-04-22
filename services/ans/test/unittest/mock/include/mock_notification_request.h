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
#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_NOTIFICATION_REQUEST_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_NOTIFICATION_REQUEST_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include "notification_request.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {
class MockNotificationRequest : public NotificationRequest {
public:
    MockNotificationRequest() = default;
    virtual ~MockNotificationRequest() = default;

    MOCK_METHOD(bool, ToJson, (nlohmann::json& jsonObject), (const, override));
};

class MockNotificationBundleOption : public NotificationBundleOption {
public:
    MockNotificationBundleOption() = default;
    virtual ~MockNotificationBundleOption() = default;

    MOCK_METHOD(bool, ToJson, (nlohmann::json& jsonObject), (const, override));
};
}  // namespace AAFwk
}  // namespace OHOS

#endif /* MOCK_OHOS_ABILITY_RUNTIME_MOCK_NOTIFICATION_REQUEST_H */