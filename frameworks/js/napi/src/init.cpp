/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "init.h"
#include "ans_template.h"
#include "cancel.h"
#include "constant.h"
#include "display_badge.h"
#include "distributed.h"
#include "disturb_mode.h"
#include "enable_notification.h"
#include "get_active.h"
#include "pixel_map_napi.h"
#include "publish.h"
#include "remove.h"
#include "slot.h"
#include "subscribe.h"
#include "unsubscribe.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

EXTERN_C_START

napi_value NotificationInit(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("subscribe", Subscribe),
        DECLARE_NAPI_FUNCTION("unsubscribe", Unsubscribe),
        DECLARE_NAPI_FUNCTION("publish", Publish),
        DECLARE_NAPI_FUNCTION("publishAsBundle", PublishAsBundle),
        DECLARE_NAPI_FUNCTION("remove", Remove),
        DECLARE_NAPI_FUNCTION("removeAll", RemoveAll),
        DECLARE_NAPI_FUNCTION("getAllActiveNotifications", GetAllActiveNotifications),
        DECLARE_NAPI_FUNCTION("getActiveNotifications", GetActiveNotifications),
        DECLARE_NAPI_FUNCTION("getActiveNotificationCount", GetActiveNotificationCount),
        DECLARE_NAPI_FUNCTION("cancel", Cancel),
        DECLARE_NAPI_FUNCTION("cancelAll", CancelAll),
        DECLARE_NAPI_FUNCTION("cancelGroup", CancelGroup),
        DECLARE_NAPI_FUNCTION("cancelAsBundle", CancelAsBundle),
        DECLARE_NAPI_FUNCTION("addSlot", AddSlot),
        DECLARE_NAPI_FUNCTION("addSlots", AddSlots),
        DECLARE_NAPI_FUNCTION("getSlot", GetSlot),
        DECLARE_NAPI_FUNCTION("getSlots", GetSlots),
        DECLARE_NAPI_FUNCTION("removeSlot", RemoveSlot),
        DECLARE_NAPI_FUNCTION("removeAllSlots", RemoveAllSlots),
        DECLARE_NAPI_FUNCTION("removeGroupByBundle", RemoveGroupByBundle),
        DECLARE_NAPI_FUNCTION("enableNotification", EnableNotification),
        DECLARE_NAPI_FUNCTION("isNotificationEnabled", IsNotificationEnabled),
        DECLARE_NAPI_FUNCTION("enableNotificationSlot", EnableNotificationSlot),
        DECLARE_NAPI_FUNCTION("isSupportTemplate", IsSupportTemplate),
        DECLARE_NAPI_FUNCTION("requestEnableNotification", RequestEnableNotification),

#ifdef ANS_FEATURE_BADGE_MANAGER
        DECLARE_NAPI_FUNCTION("displayBadge", DisplayBadge),
        DECLARE_NAPI_FUNCTION("isBadgeDisplayed", IsBadgeDisplayed),
#else
        DECLARE_NAPI_FUNCTION("displayBadge", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isBadgeDisplayed", Common::NapiReturnCapErrCb),
#endif

#ifdef ANS_FEATURE_LIVEVIEW_LOCAL_LIVEVIEW
        DECLARE_NAPI_FUNCTION("show", ShowNotification),
#else
        DECLARE_NAPI_FUNCTION("show", Common::NapiReturnCapErr),
#endif

#ifdef ANS_FEATURE_DISTRIBUTED_DB
        DECLARE_NAPI_FUNCTION("isDistributedEnabled", IsDistributedEnabled),
        DECLARE_NAPI_FUNCTION("enableDistributed", EnableDistributed),
        DECLARE_NAPI_FUNCTION("enableDistributedByBundle", EnableDistributedByBundle),
        DECLARE_NAPI_FUNCTION("enableDistributedSelf", EnableDistributedSelf),
        DECLARE_NAPI_FUNCTION("isDistributedEnabledByBundle", IsDistributedEnableByBundle),
        DECLARE_NAPI_FUNCTION("getDeviceRemindType", GetDeviceRemindType),
        DECLARE_NAPI_FUNCTION("setSyncNotificationEnabledWithoutApp", SetSyncNotificationEnabledWithoutApp),
        DECLARE_NAPI_FUNCTION("getSyncNotificationEnabledWithoutApp", GetSyncNotificationEnabledWithoutApp),
#else
        DECLARE_NAPI_FUNCTION("isDistributedEnabled", Common::NapiReturnFalseCb),
        DECLARE_NAPI_FUNCTION("enableDistributed", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("enableDistributedByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("enableDistributedSelf", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isDistributedEnabledByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getDeviceRemindType", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setSyncNotificationEnabledWithoutApp", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSyncNotificationEnabledWithoutApp", Common::NapiReturnCapErrCb),
#endif

#ifdef ANS_FEATURE_DISTURB_MANAGER
        DECLARE_NAPI_FUNCTION("setDoNotDisturbDate", SetDoNotDisturbDate),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbDate", GetDoNotDisturbDate),
        DECLARE_NAPI_FUNCTION("supportDoNotDisturbMode", SupportDoNotDisturbMode),
#else
        DECLARE_NAPI_FUNCTION("setDoNotDisturbDate", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbDate", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("supportDoNotDisturbMode", Common::NapiReturnCapErrCb),
#endif

#ifdef ANS_FEATURE_SLOT_MANAGER
        DECLARE_NAPI_FUNCTION("isNotificationSlotEnabled", IsEnableNotificationSlot),
        DECLARE_NAPI_FUNCTION("getSlotsByBundle", GetSlotsByBundle),
        DECLARE_NAPI_FUNCTION("getSlotNumByBundle", GetSlotNumByBundle),
        DECLARE_NAPI_FUNCTION("setSlotByBundle", SetSlotByBundle),
#else
        DECLARE_NAPI_FUNCTION("isNotificationSlotEnabled", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSlotsByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSlotNumByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setSlotByBundle", Common::NapiReturnCapErrCb),
#endif
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return exports;
}

/*
 * Module export function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    /*
     * Propertise define
     */
    ANS_LOGI("libnotification Init start");
    NotificationInit(env, exports);
    ConstantInit(env, exports);

    return exports;
}

/*
 * Module register function
 */
__attribute__((constructor)) void RegisterModule(void)
{
    ANS_LOGI("libnotification register start");
    napi_module_register(&_module);
}
EXTERN_C_END
}  // namespace NotificationNapi
}  // namespace OHOS