/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_DISTRIBUTED_EXTENSION_OPERATION_SERVICE_H
#define NOTIFICATION_DISTRIBUTED_EXTENSION_OPERATION_SERVICE_H

#include "notifictaion_load_utils.h"
#include "ffrt.h"
#include "notification_config_parse.h"
#include "distributed_data_define.h"
#include "itimer_info.h"
#include "ians_operation_callback.h"

#include <set>
#include <mutex>
#include <unordered_set>

namespace OHOS {
namespace Notification {

class OperationTimerInfo : public MiscServices::ITimerInfo {
public:
    OperationTimerInfo(std::string timerHashCode) : timerHashCode_(timerHashCode) {};
    virtual ~OperationTimerInfo() {};

    /**
     * When timing is up, this function will execute as call back.
     */
    void OnTrigger() override;

    /**
     * Indicates the timing type.
     */
    void SetType(const int32_t &type) override {};

    /**
     * Indicates the repeat policy.
     */
    void SetRepeat(bool repeat) override {};

    /**
     * Indicates the interval time for repeat timing.
     */
    void SetInterval(const uint64_t &interval) override {};

    /**
     * Indicates the want agent information.
     */
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override {};

private:
    std::string timerHashCode_;
};

class DistributedOperationService {
public:
    static DistributedOperationService& GetInstance();
    void AddOperation(const std::string& hashCode,
        const sptr<IAnsOperationCallback> &callback);
    void ReplyOperationResponse(const std::string& hashCode, int32_t result);
    void HandleOperationTimeOut(const std::string& hashCode);
    void RemoveOperationResponse(const std::string& hashCode);

private:
    DistributedOperationService();
    ~DistributedOperationService() = default;

private:
    ffrt::mutex mapLock_;
    std::shared_ptr<ffrt::queue> operationQueue_ = nullptr;
    std::map<std::string, uint64_t> timerMap_;
    std::map<std::string, sptr<IAnsOperationCallback>> callbackMap_;
};
}
}
#endif // NOTIFICATION_DISTRIBUTED_EXTENSION_OPERATION_SERVICE_H
