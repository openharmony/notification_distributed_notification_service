/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "mock_parameters.h"
#include "ffrt.h"

#include <mutex>

namespace OHOS {
namespace system {
std::mutex g_parameterMutex;
std::map<std::string, bool> systemParameter = {{"persist.edm.notification_disable", false}};

bool GetBoolParameter(const std::string& key, bool def)
{
    std::lock_guard<std::mutex> lock(g_parameterMutex);
    auto iter = systemParameter.find(key);
    return (iter != systemParameter.end()) ? iter->second : def;
}

void SetBoolParameter(const std::string& key, bool status)
{
    std::lock_guard<std::mutex> lock(g_parameterMutex);
    systemParameter[key] = status;
}
}
} // namespace OHOS