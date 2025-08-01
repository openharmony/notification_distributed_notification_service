/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ani_remove.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "notification_request.h"
#include "sts_bundle_option.h"
#include "sts_subscribe.h"

namespace OHOS {
namespace NotificationSubScribeSts {
using namespace OHOS::Notification;

void AniRemoveForBundle(ani_env *env, ani_object bundle, ani_object notificationKey, ani_object reasonEnum)
{
    ANS_LOGD("AniRemoveForBundle enter");
    BundleOption option;
    NotificationKey key;
    int32_t reasonType = 0;
    if (!NotificationSts::UnwrapBundleOption(env, bundle, option)) {
        ANS_LOGE("bundle is valid");
        std::string msg = "UnwrapBundleOption failed";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    if (!NotificationSts::UnWarpNotificationKey(env, notificationKey, key)) {
        ANS_LOGE("notificationKey is valid");
        std::string msg = "UnWarpNotificationKey failed";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    if (!NotificationSts::UnWarpReasonEnum(env, reasonEnum, reasonType)) {
        ANS_LOGE("enum convert failed");
        std::string msg = "UnWarpReasonEnum failed";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    if (!NotificationSts::IsValidRemoveReason(reasonType)) {
        ANS_LOGE("reasonType is valid");
        std::string msg = "reasonType is valid";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    int ret = NotificationHelper::RemoveNotification(option, key.id, key.label, reasonType);
    if (ret != ERR_OK) {
        int32_t externalErrorCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGD("StsRemoveForBundle ret %{public}d. ErrorToExternal %{public}d", ret, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowStsError(env, externalErrorCode, msg);
    }
}

void AniRemoveForHashCode(ani_env *env, ani_string hashCode, ani_object reasonEnum)
{
    ANS_LOGD("AniRemoveForHashCode enter");
    int32_t reasonType = -1;
    std::string tempStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, hashCode, tempStr)) {
        ANS_LOGE("hashCode is valid");
        std::string msg = "hashCode is valid";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    std::string hashCodeStd = NotificationSts::GetResizeStr(tempStr, NotificationSts::STR_MAX_SIZE);
    if (!NotificationSts::UnWarpReasonEnum(env, reasonEnum, reasonType)) {
        ANS_LOGE("enum convert failed");
        std::string msg = "UnWarpReasonEnum failed";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    if (!NotificationSts::IsValidRemoveReason(reasonType)) {
        ANS_LOGE("reasonType is valid");
        std::string msg = "reasonType is valid";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    ANS_LOGD("hashCode: %{public}s, reasonType: %{public}d", hashCodeStd.c_str(), reasonType);
    int ret = NotificationHelper::RemoveNotification(hashCodeStd, reasonType);
    if (ret != ERR_OK) {
        int32_t externalErrorCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGD("StsRemoveForHashCode ret %{public}d. ErrorToExternal %{public}d", ret, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowStsError(env, externalErrorCode, msg);
    }
}

void AniRemoveForHashCodes(ani_env *env, ani_object hashCodes, ani_object reasonEnum)
{
    ANS_LOGD("StsRemoveForHashCodes enter");
    std::vector<std::string> hashCodesTemp = {};
    int32_t reasonType;
    if (!NotificationSts::GetStringArrayByAniObj(env, hashCodes, hashCodesTemp)) {
        ANS_LOGE("hashCodes is valid");
        std::string msg = "hashCodes is valid";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    std::vector<std::string> hashCodesStd = {};
    for (auto hashcode : hashCodesStd) {
        hashCodesStd.emplace_back(NotificationSts::GetResizeStr(hashcode, NotificationSts::STR_MAX_SIZE));
    }
    if (!NotificationSts::UnWarpReasonEnum(env, reasonEnum, reasonType)) {
        ANS_LOGE("enum convert failed");
        std::string msg = "UnWarpReasonEnum failed";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    if (!NotificationSts::IsValidRemoveReason(reasonType)) {
        ANS_LOGE("reasonType is valid");
        std::string msg = "reasonType is valid";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    int ret = NotificationHelper::RemoveNotifications(hashCodesStd, reasonType);
    if (ret != ERR_OK) {
        int32_t externalErrorCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGD("StsRemoveForHashCodes ret %{public}d. ErrorToExternal %{public}d", ret, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowStsError(env, externalErrorCode, msg);
    }
}

void AniRemoveAll(ani_env *env)
{
    ANS_LOGD("removeAll enter");
    int ret = NotificationHelper::RemoveNotifications();
    if (ret != ERR_OK) {
        int32_t externalErrorCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGD("AniRemoveAll ret %{public}d. ErrorToExternal %{public}d", ret, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowStsError(env, externalErrorCode, msg);
    }
}

void AniRemoveAllForBundle(ani_env *env, ani_object bundle)
{
    ANS_LOGD("AniRemoveAllForBundle enter");
    BundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundle, option)) {
        ANS_LOGE("bundle is valid");
        std::string msg = "UnwrapBundleOption failed";
        OHOS::NotificationSts::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return;
    }
    int ret = NotificationHelper::RemoveAllNotifications(option);
    if (ret != ERR_OK) {
        int32_t externalErrorCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGD("StsRemoveForBundle ret %{public}d. ErrorToExternal %{public}d", ret, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowStsError(env, externalErrorCode, msg);
    }
}

void AniRemoveAllForUserId(ani_env *env, ani_double userId)
{
    ANS_LOGD("AniRemoveAllForUserId enter");
    int ret = NotificationHelper::RemoveNotifications(userId);
    if (ret != ERR_OK) {
        int32_t externalErrorCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGD("StsRemoveForBundle ret %{public}d. ErrorToExternal %{public}d", ret, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowStsError(env, externalErrorCode, msg);
    }
}
}
}
