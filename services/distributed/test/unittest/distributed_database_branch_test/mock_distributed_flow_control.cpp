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

#include "distributed_flow_control.h"

namespace {
    bool g_mockKvStoreFlowControlRet = true;
    bool g_mockKvManagerFlowControlRet = true;
}

void MockKvStoreFlowControl(bool mockRet)
{
    g_mockKvStoreFlowControlRet = mockRet;
}

void MockKvManagerFlowControl(bool mockRet)
{
    g_mockKvManagerFlowControlRet = mockRet;
}

namespace OHOS {
namespace Notification {
DistributedFlowControl::DistributedFlowControl(
    size_t kvManagerSecondMaxinum, size_t kvManagerMinuteMaxinum, size_t kvStoreSecondMaxinum,
    size_t kvStoreMinuteMaxinum)
    : kvManagerSecondMaxinum_(kvManagerSecondMaxinum),
      kvManagerMinuteMaxinum_(kvManagerMinuteMaxinum),
      kvStoreSecondMaxinum_(kvStoreSecondMaxinum),
      kvStoreMinuteMaxinum_(kvStoreMinuteMaxinum)
{}

bool DistributedFlowControl::KvManagerFlowControl()
{
    return g_mockKvManagerFlowControlRet;
}

bool DistributedFlowControl::KvStoreFlowControl()
{
    return g_mockKvStoreFlowControlRet;
}
}  // namespace Notification
}  // namespace OHOS
