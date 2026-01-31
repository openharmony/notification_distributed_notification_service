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
#include "service_priority_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "advanced_notification_service.h"
#include "ans_permission_def.h"
#include "mock_notification_request.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        
        service->InitPublishProcess();
        service->CreateDialogManager();
        std::string stringData = ConsumePrintableString(fuzzData, fuzzData->ConsumeIntegralInRange<int32_t>(0, 15));
        sptr<NotificationRequest> request = ObjectBuilder<NotificationRequest>::Build(fuzzData);

        bool enable = fuzzData->ConsumeBool();
        service->SetPriorityEnabled(enable);
        service->SetPriorityEnabledInner(enable);
        service->IsPriorityEnabled(enable);

        int32_t enableStatus = fuzzData->ConsumeIntegralInRange<int32_t>(0, 6);
        std::string name = fuzzData->ConsumeRandomLengthString();
        int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
        sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(name, uid);
        service->SetPriorityEnabledByBundle(bundleOption, enableStatus);

        service->TriggerUpdatePriorityType(request);

        service->SetBundlePriorityConfig(bundleOption, stringData);
        service->GetBundlePriorityConfig(bundleOption, stringData);

        std::map<sptr<NotificationBundleOption>, bool> priorityEnableMap1;
        priorityEnableMap1.emplace(bundleOption, enable);
        service->SetPriorityEnabledByBundles(priorityEnableMap1);

        std::vector<sptr<NotificationBundleOption>> bundles;
        bundles.emplace_back(bundleOption);
        std::map<sptr<NotificationBundleOption>, bool> priorityEnableMap2;
        service->GetPriorityEnabledByBundles(bundles, priorityEnableMap2);

        service->SetPriorityIntelligentEnabled(enable);
        service->IsPriorityIntelligentEnabled(enable);

        int32_t strategy = fuzzData->ConsumeIntegralInRange<int64_t>(0, 64);
        std::map<sptr<NotificationBundleOption>, int64_t> strategyMap1;
        strategyMap1.emplace(bundleOption, strategy);
        std::map<sptr<NotificationBundleOption>, int64_t> strategyMap2;
        service->SetPriorityStrategyByBundles(strategyMap1);
        service->GetPriorityStrategyByBundles(bundles, strategyMap2);

        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
