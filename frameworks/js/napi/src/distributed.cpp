/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed.h"

namespace OHOS {
namespace NotificationNapi {
const int ENABLED_MAX_PARA = 2;
const int ENABLED_MIN_PARA = 1;
const int ENABLED_BUNDLE_MAX_PARA = 3;
const int ENABLED_BUNDLE_MIN_PARA = 2;
const int IS_ENABLED_BUNDLE_MAX_PARA = 2;
const int IS_ENABLED_BUNDLE_MIN_PARA = 1;
const int ENABLED_SYNC_MAX_PARA = 3;
const int ENABLED_SYNC_MIN_PARA = 2;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnabledParams &params)
{
    ANS_LOGI("enter");

    size_t argc = ENABLED_MAX_PARA;
    napi_value argv[ENABLED_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ENABLED_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;

    // argv[0]: enable
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM0], &params.enable);

    // argv[1]:callback
    if (argc >= ENABLED_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnabledByBundleParams &params)
{
    ANS_LOGI("enter");

    size_t argc = ENABLED_BUNDLE_MAX_PARA;
    napi_value argv[ENABLED_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ENABLED_BUNDLE_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments");
        return nullptr;
    }

    // argv[0]: bundle
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected");
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed");
        return nullptr;
    }

    // argv[1]: enable
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM1], &params.enable);

    // argv[2]:callback
    if (argc >= ENABLED_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, IsEnabledByBundleParams &params)
{
    ANS_LOGI("enter");

    size_t argc = IS_ENABLED_BUNDLE_MAX_PARA;
    napi_value argv[IS_ENABLED_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < IS_ENABLED_BUNDLE_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        return nullptr;
    }

    // argv[0]: bundle
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Parameter type error. Object expected.");
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= IS_ENABLED_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackIsDistributedEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }
    ANS_LOGI("IsDistributedEnabled work complete.");
    AsyncCallbackInfoIsEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabled *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->enable, &result);
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete isDistributedEnabled callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value IsDistributedEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoIsEnabled {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create isDistributedEnabled string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isDistributedEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("IsDistributedEnabled work excute");
            AsyncCallbackInfoIsEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabled *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::IsDistributedEnabled(asynccallbackinfo->enable);
                ANS_LOGI("IsDistributedEnabled enable = %{public}d", asynccallbackinfo->enable);
            }
        },
        AsyncCompleteCallbackIsDistributedEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue isDistributedEnabled work failed return: %{public}d", status);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("isDistributedEnabled callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value EnableDistributed(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    EnabledParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabled {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("AsyncCallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create enableDistributed string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableDistributed", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("EnableDistributed work excute.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::EnableDistributed(asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("EnableDistributed work complete.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete enableDistributed callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("EnableDistributed work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue enableDistributed work failed return: %{public}d", status);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, params.callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("enableDistributed callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value EnableDistributedByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    EnabledByBundleParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnabledByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabledByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("AsyncCallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create enableDistributedByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableDistributedByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("EnableDistributedByBundle work excute.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::EnableDistributedByBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("EnableDistributedByBundle work complete.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete enableDistributedByBundle callback reference");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("EnableDistributedByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue enableDistributedByBundle work failed return: %{public}d", status);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, params.callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("enableDistributedByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value EnableDistributedSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    EnabledParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabled {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGI("Create enableDistributedSelf string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableDistributedSelf", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("EnableDistributedSelf work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::EnableDistributedSelf(asynccallbackinfo->params.enable);
                ANS_LOGI("EnableDistributedSelf enable = %{public}d", asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("EnableDistributedSelf work complete.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete enableDistributedSelf callback reference");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("EnableDistributedSelf work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue enableDistributedSelf work failed return: %{public}d", status);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, params.callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("enableDistributedSelf callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackIsDistributedEnableByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("IsDistributedEnableByBundle work complete.");
    AsyncCallbackInfoIsEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabledByBundle *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->enable, &result);
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete isDistributedEnableByBundle callback reference");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value IsDistributedEnableByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    IsEnabledByBundleParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnabledByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnabledByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create isDistributedEnableByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isDistributedEnableByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("IsDistributedEnableByBundle work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoIsEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsDistributedEnableByBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->enable);
            }
        },
        AsyncCompleteCallbackIsDistributedEnableByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue isDistributedEnableByBundle work failed return: %{public}d", status);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, params.callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("isDistributedEnableByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackGetDeviceRemindType(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalidity async callback data");
        return;
    }
    ANS_LOGI("GetDeviceRemindType work complete.");
    AsyncCallbackInfoGetRemindType *asynccallbackinfo = static_cast<AsyncCallbackInfoGetRemindType *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            ANS_LOGD("errorCode is not ERR_OK.");
            result = Common::NapiGetNull(env);
        } else {
            DeviceRemindType outType = DeviceRemindType::IDLE_DONOT_REMIND;
            if (!Common::DeviceRemindTypeCToJS(asynccallbackinfo->remindType, outType)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
            napi_create_int32(env, (int32_t)outType, &result);
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete getDeviceRemindType callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetDeviceRemindType(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoGetRemindType {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo fail.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getDeviceRemindType string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getDeviceRemindType", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetDeviceRemindType work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetRemindType *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetDeviceRemindType(asynccallbackinfo->remindType);
            }
        },
        AsyncCompleteCallbackGetDeviceRemindType,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue getDeviceRemindType work failed return: %{public}d", status);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getDeviceRemindType callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnabledWithoutAppParams &params)
{
    ANS_LOGI("enter");

    size_t argc = ENABLED_SYNC_MAX_PARA;
    napi_value argv[ENABLED_SYNC_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc < ENABLED_SYNC_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        return nullptr;
    }

    // argv[0]: userId
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Argument type error. Number expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &params.userId));
    if (params.userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Wrong userId[%{public}d].", params.userId);
        return nullptr;
    }

    // argv[1]: enable
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM1], &params.enable);

    // argv[2]:callback
    if (argc >= ENABLED_SYNC_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value SetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    EnabledWithoutAppParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::JSParaError(env, params.callback);
    }

    AsyncCallbackInfoEnabledWithoutApp *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabledWithoutApp {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create SetSyncNotificationEnabledWithoutApp string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "SetSyncNotificationEnabledWithoutApp", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("SetSyncNotificationEnabledWithoutApp work excute.");
            AsyncCallbackInfoEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetSyncNotificationEnabledWithoutApp(
                    asynccallbackinfo->params.userId, asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("SetSyncNotificationEnabledWithoutApp work complete.");
            AsyncCallbackInfoEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete setSyncNotificationEnabledWithoutApp callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    if (napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated) != napi_ok) {
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete setSyncNotificationEnabledWithoutApp callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, params.callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("setSyncNotificationEnabledWithoutApp callback is nullptr.");
        return Common::NapiGetNull(env);
    }
    return promise;
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, GetEnabledWithoutAppParams &params)
{
    ANS_LOGI("enter");

    size_t argc = ENABLED_SYNC_MIN_PARA;
    napi_value argv[ENABLED_SYNC_MIN_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ENABLED_SYNC_MIN_PARA - 1) {
        ANS_LOGE("Wrong number of arguments.");
        return nullptr;
    }

    // argv[0]: userId
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &params.userId));
    if (params.userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Wrong userId[%{public}d].", params.userId);
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= ENABLED_SYNC_MIN_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value GetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    GetEnabledWithoutAppParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::JSParaError(env, params.callback);
    }

    AsyncCallbackInfoGetEnabledWithoutApp *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetEnabledWithoutApp {
        .env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create GetSyncNotificationEnabledWithoutApp string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "GetSyncNotificationEnabledWithoutApp", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetSyncNotificationEnabledWithoutApp work excute.");
            AsyncCallbackInfoGetEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoGetEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetSyncNotificationEnabledWithoutApp(
                    asynccallbackinfo->params.userId, asynccallbackinfo->enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("GetSyncNotificationEnabledWithoutApp work complete.");
            AsyncCallbackInfoGetEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoGetEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                if (asynccallbackinfo->info.errorCode != ERR_OK) {
                    result = Common::NapiGetNull(env);
                } else {
                    napi_get_boolean(env, asynccallbackinfo->enable, &result);
                }
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete getSyncNotificationEnabledWithoutApp callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    if (napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated) != napi_ok) {
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
        return Common::JSParaError(env, params.callback);
    }

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("GetSyncNotificationEnabledWithoutApp callback is nullptr.");
        return Common::NapiGetNull(env);
    }
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS