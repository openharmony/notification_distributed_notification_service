/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mock_time_service_client.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {
namespace {
bool g_mockCreateTimerFailed = false;
bool g_mockStartTimerFailed = false;
bool g_destroyTimerCalled = false;
int g_createTimerCallCount = 0;
}

void MockCreateTimerFailed(bool mockCreateTimerFailed)
{
    g_mockCreateTimerFailed = mockCreateTimerFailed;
}

void MockStartTimerFailed(bool mockStartTimerFailed)
{
    g_mockStartTimerFailed = mockStartTimerFailed;
}

bool IsDestroyTimerCalled()
{
    return g_destroyTimerCalled;
}

int GetCreateTimerCallCount()
{
    return g_createTimerCallCount;
}

void ResetTimeServiceMock()
{
    g_mockCreateTimerFailed = false;
    g_mockStartTimerFailed = false;
    g_destroyTimerCalled = false;
    g_createTimerCallCount = 0;
}

} // namespace Notification

namespace MiscServices {

uint64_t TimeServiceClient::CreateTimer(std::shared_ptr<ITimerInfo> timerOptions)
{
    Notification::g_createTimerCallCount++;
    if (Notification::g_mockCreateTimerFailed) {
        return 0;
    }

    return 1;
}

bool TimeServiceClient::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    return !Notification::g_mockStartTimerFailed;
}

bool TimeServiceClient::DestroyTimer(uint64_t timerId)
{
    Notification::g_destroyTimerCalled = true;
    return true;
}

} // namespace MiscServices
} // namespace OHOS