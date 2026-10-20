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
#include "napi/native_api.h"
#include "stream_metrics.h"

static napi_value ResetMetrics(napi_env env, napi_callback_info info)
{
    StreamMetrics::GetInstance().Reset();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value MarkSwitchStart(napi_env env, napi_callback_info info)
{
    StreamMetrics::GetInstance().MarkSwitchStart();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value MarkFirstFrame(napi_env env, napi_callback_info info)
{
    StreamMetrics::GetInstance().MarkFirstFrame();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value MarkSwitchEnd(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    bool success = false;
    if (argc >= 1) {
        napi_get_value_bool(env, args[0], &success);
    }
    StreamMetrics::GetInstance().MarkSwitchEnd(success);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value MarkAudioPulse(napi_env env, napi_callback_info info)
{
    StreamMetrics::GetInstance().MarkAudioPulse();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value GetMetrics(napi_env env, napi_callback_info info)
{
    StreamMetricsData data = StreamMetrics::GetInstance().GetMetrics();
    napi_value obj;
    napi_create_object(env, &obj);

    napi_value val;
    napi_create_int64(env, data.switchStartMs, &val);
    napi_set_named_property(env, obj, "switchStartMs", val);

    napi_create_int64(env, data.switchEndMs, &val);
    napi_set_named_property(env, obj, "switchEndMs", val);

    napi_create_int64(env, data.firstFrameMs, &val);
    napi_set_named_property(env, obj, "firstFrameMs", val);

    napi_create_int64(env, data.audioPulseMs, &val);
    napi_set_named_property(env, obj, "audioPulseMs", val);

    napi_create_int32(env, data.frameCount, &val);
    napi_set_named_property(env, obj, "frameCount", val);

    napi_get_boolean(env, data.switchSuccess, &val);
    napi_set_named_property(env, obj, "switchSuccess", val);

    return obj;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        { "resetMetrics", nullptr, ResetMetrics, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "markSwitchStart", nullptr, MarkSwitchStart, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "markFirstFrame", nullptr, MarkFirstFrame, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "markSwitchEnd", nullptr, MarkSwitchEnd, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "markAudioPulse", nullptr, MarkAudioPulse, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "getMetrics", nullptr, GetMetrics, nullptr, nullptr, nullptr, napi_default, nullptr },
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void)
{
    napi_module_register(&demoModule);
}
