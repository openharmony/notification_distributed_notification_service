/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_ffi/cj_common_ffi.h"

extern "C" {
FFI_EXPORT int FfiOHOSNotificationManagerPublish = 0;
FFI_EXPORT int FfiOHOSNotificationManagerCancel = 0;
FFI_EXPORT int FfiOHOSNotificationManagerCancelAll = 0;
FFI_EXPORT int FfiOHOSNotificationManagerAddSlot = 0;
FFI_EXPORT int FfiOHOSNotificationManagerIsNotificationEnabled = 0;
FFI_EXPORT int FfiOHOSNotificationManagerSetBadgeNumber = 0;
FFI_EXPORT int FfiOHOSNotificationManagerRequestEnableNotification = 0;
FFI_EXPORT int FfiOHOSNotificationManagerRequestEnableNotificationWithContext = 0;
FFI_EXPORT int FfiOHOSNotificationManagerIsDistributedEnabled = 0;
FFI_EXPORT int FfiOHOSNotificationManagerGetSlot = 0;
FFI_EXPORT int FfiOHOSNotificationManagerGetSlots = 0;
FFI_EXPORT int FfiOHOSNotificationManagerRemoveSlot = 0;
FFI_EXPORT int FfiOHOSNotificationManagerRemoveAllSlots = 0;
FFI_EXPORT int FfiOHOSNotificationManagerGetActiveNotificationCount = 0;
FFI_EXPORT int FfiOHOSNotificationManagerGetActiveNotifications = 0;
FFI_EXPORT int FfiOHOSNotificationManagerCancelGroup = 0;
FFI_EXPORT int FfiOHOSNotificationManagerIsSupportTemplate = 0;

FFI_EXPORT int FfiOHOSNotificationManagerSetNotificationEnable = 0;
FFI_EXPORT int FfiOHOSNotificationManagerDisplayBadge = 0;
FFI_EXPORT int FfiOHOSNotificationManagerIsBadgeDisplayed = 0;
FFI_EXPORT int FfiOHOSNotificationManagerSetSlotFlagsByBundle = 0;
FFI_EXPORT int FfiOHOSNotificationManagerGetSlotFlagsByBundle = 0;
FFI_EXPORT int FfiOHOSNotificationManagerGetSlotNumByBundle = 0;
FFI_EXPORT int FfiOHOSNotificationManagerRemoveGroupByBundle = 0;
}
