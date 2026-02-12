/*
* Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "notification_clone_priority_service.h"

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "parameters.h"

namespace OHOS {
namespace Notification {
constexpr int32_t INVALID_APP_INDEX = -1;
constexpr int32_t  PRIORITY_RESTORE_VERSION_V1 = 1;
constexpr int32_t PRIORITY_RESTORE_VERSION_V2 = 2;
int32_t NotificationClonePriority::restoreVer_ = PRIORITY_RESTORE_VERSION_V1;
bool NotificationClonePriority::fromUnSupportPriority_ = true;

std::shared_ptr<NotificationClonePriority> NotificationClonePriority::GetInstance()
{
    static std::shared_ptr<NotificationClonePriority> instance =
        std::make_shared<NotificationClonePriority>();
    return instance;
}

ErrCode NotificationClonePriority::OnBackup(nlohmann::json &jsonObject)
{
    bool isSupportPriority =
        (OHOS::system::GetParameter("const.systemui.priority_notification_enabled", "false") == "true");
    if (!isSupportPriority) {
        ANS_LOGI("OnBackup not support Priority.");
        return ERR_OK;
    }
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationPreferences::GetInstance()->GetAllClonePriorityInfo(userId, cloneInfos);
    if (cloneInfos.empty()) {
        ANS_LOGI("Notification priority info is empty.");
        return ERR_OK;
    }
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
        ANS_LOGD("backup clone info: %{public}s.", cloneInfo.Dump().c_str());
    }
    return ERR_OK;
}

void NotificationClonePriority::OnRestoreEnd(int32_t userId)
{
    std::unique_lock lock(lock_);
    if (!priorityInfo_.empty()) {
        NotificationPreferences::GetInstance()->DelClonePriorityInfos(userId, priorityInfo_);
        priorityInfo_.clear();
    }
    clonedSystemApps_.clear();
    fromUnSupportPriority_ = true;
    restoreVer_ = PRIORITY_RESTORE_VERSION_V1;
    ANS_LOGW("Priority on clear Restore");
}

void NotificationClonePriority::OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps)
{
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGI("Notification priority profile list is null or not array.");
        return;
    }
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::unique_lock lock(lock_);
    if (!priorityInfo_.empty()) {
        NotificationPreferences::GetInstance()->DelClonePriorityInfos(userId, priorityInfo_);
        priorityInfo_.clear();
    }
    for (const auto &jsonNode : jsonObject) {
        NotificationClonePriorityInfo cloneInfo;
        if (!cloneInfo.FromJson(jsonNode)) {
            continue;
        }
        if (cloneInfo.GetClonePriorityType() ==
            NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_INTELLIGENT_ENABLE) {
            restoreVer_ = PRIORITY_RESTORE_VERSION_V2;
        }
        priorityInfo_.emplace_back(cloneInfo);
    }
    if (priorityInfo_.empty()) {
        ANS_LOGI("Priority info is null");
        return;
    }
    fromUnSupportPriority_ = false;
    ANS_LOGI("NotificationClonePriority OnRestore priorityInfo size %{public}zu, resotreVer: %{public}d",
        priorityInfo_.size(), restoreVer_);
    clonedSystemApps_.clear();
    BatchRestoreSystemAppsPriorityInfo(systemApps, userId);
    NotificationPreferences::GetInstance()->UpdateClonePriorityInfos(userId, priorityInfo_);
    return;
}

void NotificationClonePriority::BatchRestoreSystemAppsPriorityInfo(
    const std::set<std::string> &systemApps, const int32_t userId)
{
    for (std::string bundleName : systemApps) {
        int32_t uid = NotificationCloneUtil::GetBundleUid(bundleName, userId, INVALID_APP_INDEX);
        if (uid <= DEFAULT_UID) {
            continue;
        }
        SetDefaultPriorityInfo(uid, bundleName);
    }
    for (auto iter = priorityInfo_.begin(); iter != priorityInfo_.end();) {
        NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE type = iter->GetClonePriorityType();
        if ((restoreVer_ == PRIORITY_RESTORE_VERSION_V1 &&
            type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE) ||
            (restoreVer_ == PRIORITY_RESTORE_VERSION_V2 &&
            type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_INTELLIGENT_ENABLE)) {
            AdvancedNotificationService::GetInstance()->SetPriorityIntelligentEnabledInner(
                static_cast<NotificationConstant::SWITCH_STATE>(iter->GetSwitchState()));
            iter = priorityInfo_.erase(iter);
            continue;
        }

        if (systemApps.find(iter->GetBundleName()) == systemApps.end()) {
            ++iter;
            continue;
        }
        int32_t uid = NotificationCloneUtil::GetBundleUid(iter->GetBundleName(), userId, iter->GetAppIndex());
        if (uid <= DEFAULT_UID) {
            ANS_LOGW("OnRestore systemApps priorityInfo fail, GetBundleUid fail.");
            ++iter;
            continue;
        }
        clonedSystemApps_.insert(iter->GetBundleName());
        RestoreBundlePriorityInfo(uid, *iter, restoreVer_);
        iter = priorityInfo_.erase(iter);
    }
    return;
}

void NotificationClonePriority::SetDefaultPriorityInfo(const int32_t uid, const std::string &bundleName)
{
    sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bo == nullptr) {
        ANS_LOGW("null bundleOption");
        return;
    }

    // cfg
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bo, "");

    // V2
    std::map<sptr<NotificationBundleOption>, NotificationConstant::SWITCH_STATE> priorityEnableMap;
    priorityEnableMap.emplace(bo, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundlesInner(priorityEnableMap);

    // strategy
    std::map<sptr<NotificationBundleOption>, int64_t> priorityStrategyMap;
    priorityStrategyMap.emplace(bo, PRIORITY_STRATEGY_DEFAULT);
    AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundlesInner(priorityStrategyMap);
    return;
}

void NotificationClonePriority::RestoreBundlePriorityInfo(
    const int32_t uid, const NotificationClonePriorityInfo &priorityInfo, const int32_t &restoreVer)
{
    sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(priorityInfo.GetBundleName(), uid);
    if (bo == nullptr) {
        ANS_LOGW("null bundleOption");
        return;
    }

    NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE type = priorityInfo.GetClonePriorityType();
    if (type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_CONFIG) {
        AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bo, priorityInfo.GetPriorityConfig());
    }
    if (restoreVer == PRIORITY_RESTORE_VERSION_V1) {
        if (type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE) {
            std::map<sptr<NotificationBundleOption>, NotificationConstant::SWITCH_STATE> priorityEnableMap;
            int32_t bundleSwitchState = priorityInfo.GetSwitchState();
            NotificationConstant::SWITCH_STATE priorityBundleEnable = (bundleSwitchState ==
                static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::DISABLE) ?
                NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF :
                NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
            priorityEnableMap.emplace(bo, priorityBundleEnable);
            AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundlesInner(priorityEnableMap);

            std::map<sptr<NotificationBundleOption>, int64_t> priorityStrategyMap;
            if (bundleSwitchState == static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE)) {
                priorityStrategyMap.emplace(bo,
                    static_cast<int64_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
                AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundlesInner(priorityStrategyMap);
            } else {
                priorityStrategyMap.emplace(bo, static_cast<int64_t>(PRIORITY_STRATEGY_INTELLIGENT));
                AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundlesInner(priorityStrategyMap);
            }
        }
    }
    if (restoreVer == PRIORITY_RESTORE_VERSION_V2) {
        if (type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE_V2) {
            std::map<sptr<NotificationBundleOption>, NotificationConstant::SWITCH_STATE> prEnableMap;
            prEnableMap.emplace(bo, static_cast<NotificationConstant::SWITCH_STATE>(priorityInfo.GetSwitchState()));
            AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundlesInner(prEnableMap);
        }
        if (type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_STRATEGY_FOR_BUNDLE) {
            std::map<sptr<NotificationBundleOption>, int64_t> priorityStrategyMap;
            priorityStrategyMap.emplace(bo, static_cast<int64_t>(priorityInfo.GetSwitchState()));
            AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundlesInner(priorityStrategyMap);
        }
    }
}

void NotificationClonePriority::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGI("Handle bundle event: %{public}s, %{public}d, %{public}d, %{public}d, "
        "priorityInfoSize: %{public}zu, fromUnSupportPriority: %{public}d.",
        bundleName.c_str(), appIndex, userId, uid, priorityInfo_.size(), fromUnSupportPriority_);
    std::unique_lock lock(lock_);
    if (fromUnSupportPriority_ || clonedSystemApps_.find(bundleName) != clonedSystemApps_.end()) {
        return;
    }
    SetDefaultPriorityInfo(uid, bundleName);
    for (auto iter = priorityInfo_.begin(); iter != priorityInfo_.end();) {
        if (iter->GetClonePriorityType() == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE ||
            iter->GetClonePriorityType() ==
            NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_INTELLIGENT_ENABLE ||
            iter->GetBundleName() != bundleName || iter->GetAppIndex() != appIndex) {
            iter++;
            continue;
        }
        RestoreBundlePriorityInfo(uid, *iter, restoreVer_);
        NotificationPreferences::GetInstance()->DelClonePriorityInfo(userId, *iter);
        iter = priorityInfo_.erase(iter);
    }
    return;
}

void NotificationClonePriority::OnUserSwitch(int32_t userId)
{
    std::unique_lock lock(lock_);
    priorityInfo_.clear();
    NotificationPreferences::GetInstance()->GetClonePriorityInfos(userId, priorityInfo_);
    ANS_LOGI("NotificationClonePriority OnUserSwitch priorityInfo size %{public}zu.", priorityInfo_.size());
}
}
}
