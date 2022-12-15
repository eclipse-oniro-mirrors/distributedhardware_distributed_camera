/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "constants.h"
#include "dcamera_low_latency.h"
#include "device_type.h"
#include "distributed_camera_errno.h"
#include "distributed_hardware_log.h"
#include "ipublisher_listener.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DCameraLowLatency);

int32_t DCameraLowLatency::EnableLowLatency()
{
    DHLOGD("Enable low latency start.");
    if (refCount_ > REF_INITIAL) {
        refCount_++;
        DHLOGD("No need to enable low latency, refCount just plus one and now is: %d.", refCount_.load());
        return DCAMERA_OK;
    }
    std::shared_ptr<DistributedHardwareFwkKit> dHFwkKit = GetDHFwkKit();
    if (dHFwkKit == nullptr) {
        DHLOGE("Get dHFwkKit is null when enable low latency.");
        return DCAMERA_BAD_VALUE;
    }
    nlohmann::json enable = {
        {DH_TYPE, DHType::CAMERA},
        {LOW_LATENCY_ENABLE, true},
    };
    dHFwkKit->PublishMessage(DHTopic::TOPIC_LOW_LATENCY, enable.dump());
    refCount_++;
    DHLOGD("Enable low latency success and now refCount is: %d", refCount_.load());
    return DCAMERA_OK;
}

int32_t DCameraLowLatency::DisableLowLatency()
{
    DHLOGD("Disable low latency start.");
    if (refCount_ == REF_INITIAL) {
        DHLOGD("No need to disable low latency, refCount is zero.");
        return DCAMERA_OK;
    }
    if (refCount_ > REF_NORMAL) {
        refCount_--;
        DHLOGD("No need to disable low latency, refCount just minus one and now is: %d.", refCount_.load());
        return DCAMERA_OK;
    }
    std::shared_ptr<DistributedHardwareFwkKit> dHFwkKit = GetDHFwkKit();
    if (dHFwkKit == nullptr) {
        DHLOGE("Get dHFwkKit is null when disable low latency.");
        return DCAMERA_BAD_VALUE;
    }
    nlohmann::json disable = {
        {DH_TYPE, DHType::CAMERA},
        {LOW_LATENCY_ENABLE, false},
    };
    dHFwkKit->PublishMessage(DHTopic::TOPIC_LOW_LATENCY, disable.dump());
    refCount_--;
    DHLOGD("Disable low latency success.");
    return DCAMERA_OK;
}

std::shared_ptr<DistributedHardwareFwkKit> DCameraLowLatency::GetDHFwkKit()
{
    std::lock_guard<std::mutex> lock(dHFwkKitMutex_);
    if (dHFwkKit_ == nullptr) {
        dHFwkKit_ = std::make_shared<DistributedHardwareFwkKit>();
    }
    return dHFwkKit_;
}
} // namespace DistributedHardware
} // namespace OHOS