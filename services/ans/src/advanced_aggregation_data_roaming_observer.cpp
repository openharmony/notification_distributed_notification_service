/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "advanced_aggregation_data_roaming_observer.h"
#include "advanced_notification_service.h"
#include "notification_extension_wrapper.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
AdvancedAggregationDataRoamingObserver::AdvancedAggregationDataRoamingObserver()
{}

AdvancedAggregationDataRoamingObserver::~AdvancedAggregationDataRoamingObserver() = default;

void AdvancedAggregationDataRoamingObserver::OnChange()
{
    std::string enable = "";
    AdvancedNotificationService::GetInstance()->GetUnifiedGroupInfoFromDb(enable);
    ANS_LOGI("GetUnifiedGroupInfoFromDb enter, enable:%{public}s", enable.c_str());

#ifdef ENABLE_ANS_AGGREGATION
    EXTENTION_WRAPPER->SetlocalSwitch(enable);
    AdvancedNotificationService::GetInstance()->ClearAllNotificationGroupInfo(enable);
#else
    ANS_LOGD("Not enabled ans_ext");
#endif
}
} // namespace Telephony
} // namespace OHOS
