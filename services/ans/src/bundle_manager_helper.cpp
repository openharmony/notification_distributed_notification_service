/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "bundle_manager_helper.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
BundleManagerHelper::BundleManagerHelper()
{
    deathRecipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&BundleManagerHelper::OnRemoteDied, this, std::placeholders::_1));
    if (deathRecipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
}

BundleManagerHelper::~BundleManagerHelper()
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Disconnect();
}

void BundleManagerHelper::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Disconnect();
}

std::string BundleManagerHelper::GetBundleNameByUid(int32_t uid)
{
    std::string bundle;

    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ != nullptr) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        bundleMgr_->GetNameForUid(uid, bundle);
        IPCSkeleton::SetCallingIdentity(identity);
    }

    return bundle;
}
bool BundleManagerHelper::IsSystemApp(int32_t uid)
{
    bool isSystemApp = false;

    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ != nullptr) {
        isSystemApp = bundleMgr_->CheckIsSystemAppByUid(uid);
    }

    return isSystemApp;
}

bool BundleManagerHelper::CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr");
        return false;
    }
    return CheckApiCompatibility(bundleOption->GetBundleName(), bundleOption->GetUid());
}

bool BundleManagerHelper::CheckApiCompatibility(const std::string &bundleName, const int32_t &uid)
{
    AppExecFwk::BundleInfo bundleInfo;
    int32_t callingUserId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, callingUserId);
    if (!GetBundleInfoByBundleName(bundleName, callingUserId, bundleInfo)) {
        ANS_LOGE("Failed to GetBundleInfoByBundleName, bundlename = %{public}s",
            bundleName.c_str());
        return false;
    }

    for (auto abilityInfo : bundleInfo.abilityInfos) {
        if (abilityInfo.isStageBasedModel) {
            return false;
        }
    }
    return true;
}

bool BundleManagerHelper::GetBundleInfoByBundleName(
    const std::string bundle, const int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();

    if (bundleMgr_ == nullptr) {
        return false;
    }
    bool ret = false;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    ret = bundleMgr_->GetBundleInfo(bundle, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}

void BundleManagerHelper::Connect()
{
    if (bundleMgr_ != nullptr) {
        return;
    }

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        return;
    }

    bundleMgr_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->AddDeathRecipient(deathRecipient_);
    }
}

void BundleManagerHelper::Disconnect()
{
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        bundleMgr_ = nullptr;
    }
}

int32_t BundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    int32_t uid = -1;

    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ != nullptr) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        uid = bundleMgr_->GetUidByBundleName(bundle, userId);
        if (uid < 0) {
            ANS_LOGW("get invalid uid of bundle %{public}s in userId %{public}d", bundle.c_str(), userId);
        }
        IPCSkeleton::SetCallingIdentity(identity);
    }

    return uid;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
bool BundleManagerHelper::GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ != nullptr) {
        AppExecFwk::ApplicationInfo appInfo;
        if (bundleMgr_->GetApplicationInfo(
            bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo)) {
            ANS_LOGD("APPLICATION_INFO distributed enabled %{public}d", appInfo.distributedNotificationEnabled);
            return appInfo.distributedNotificationEnabled;
        }
    }

    ANS_LOGD("APPLICATION_INFO distributed enabled is default");
    return DEFAULT_DISTRIBUTED_ENABLE_IN_APPLICATION_INFO;
}
#endif

bool BundleManagerHelper::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ == nullptr) {
        return false;
    }
    int32_t callingUserId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(userId, callingUserId);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool ret = bundleMgr_->GetBundleInfo(bundleName, flag, bundleInfo, callingUserId);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}

bool BundleManagerHelper::GetBundleInfos(
    const AppExecFwk::BundleFlag flag, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();

    if (bundleMgr_ == nullptr) {
        return false;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool ret = bundleMgr_->GetBundleInfos(flag, bundleInfos, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}

int32_t BundleManagerHelper::GetAppIndexByUid(const int32_t uid)
{
    int32_t appIndex = 0;
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (nullptr == bundleMgr_) {
        return appIndex;
    }
    std::string bundleName;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr_->GetNameAndIndexForUid(uid, bundleName, appIndex);
    IPCSkeleton::SetCallingIdentity(identity);
    return appIndex;
}

int32_t BundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId,
    const int32_t appIndex)
{
    int32_t uid = -1;
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (bundleMgr_ != nullptr) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        uid = bundleMgr_->GetUidByBundleName(bundle, userId, appIndex);
        if (uid < 0) {
            ANS_LOGW("get invalid uid of bundle %{public}s in userId %{public}d", bundle.c_str(), userId);
        }
        IPCSkeleton::SetCallingIdentity(identity);
    }
    return uid;
}
}  // namespace Notification
}  // namespace OHOS
