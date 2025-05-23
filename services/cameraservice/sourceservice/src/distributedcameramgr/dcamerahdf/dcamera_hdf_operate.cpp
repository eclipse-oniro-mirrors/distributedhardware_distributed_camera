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

#include "dcamera_hdf_operate.h"

#include <hdf_base.h>
#include <hdf_device_class.h>

#include "anonymous_string.h"
#include "distributed_camera_errno.h"
#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DCameraHdfOperate);

void DCameraHdfServStatListener::OnReceive(const ServiceStatus& status)
{
    DHLOGI("service status on receive");
    if (status.serviceName == CAMERA_SERVICE_NAME || status.serviceName == PROVIDER_SERVICE_NAME) {
        callback_(status);
    }
}

int32_t DCameraHdfOperate::LoadDcameraHDFImpl()
{
    if (cameraServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START &&
        providerServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
        DHLOGI("service has already start");
        return DCAMERA_OK;
    }
    OHOS::sptr<IServiceManager> servMgr = IServiceManager::Get();
    OHOS::sptr<IDeviceManager> devmgr = IDeviceManager::Get();
    if (servMgr == nullptr || devmgr == nullptr) {
        DHLOGE("get hdi service manager or device manager failed!");
        return DCAMERA_BAD_VALUE;
    }

    ::OHOS::sptr<IServStatListener> listener(
        new DCameraHdfServStatListener(DCameraHdfServStatListener::StatusCallback([&](const ServiceStatus& status) {
            DHLOGI("LoadCameraService service status callback, serviceName: %{public}s, status: %{public}d",
                status.serviceName.c_str(), status.status);
            std::unique_lock<std::mutex> lock(hdfOperateMutex_);
            if (status.serviceName == CAMERA_SERVICE_NAME) {
                cameraServStatus_.store(status.status);
                hdfOperateCon_.notify_one();
            } else if (status.serviceName == PROVIDER_SERVICE_NAME) {
                providerServStatus_.store(status.status);
                hdfOperateCon_.notify_one();
            }
        })));
    if (servMgr->RegisterServiceStatusListener(listener, DEVICE_CLASS_CAMERA) != 0) {
        DHLOGE("RegisterServiceStatusListener failed!");
        return DCAMERA_BAD_VALUE;
    }

    DHLOGI("Load camera service.");
    int32_t ret = devmgr->LoadDevice(CAMERA_SERVICE_NAME);
    if (ret != HDF_SUCCESS && ret != HDF_ERR_DEVICE_BUSY) {
        return DCAMERA_BAD_OPERATE;
    }
    if (WaitLoadCameraService() != DCAMERA_OK) {
        return DCAMERA_BAD_OPERATE;
    }

    ret = devmgr->LoadDevice(PROVIDER_SERVICE_NAME);
    if (ret != HDF_SUCCESS && ret != HDF_ERR_DEVICE_BUSY) {
        DHLOGE("Load provider service failed!");
        return DCAMERA_BAD_OPERATE;
    }
    if (WaitLoadProviderService() != DCAMERA_OK) {
        return DCAMERA_BAD_OPERATE;
    }

    if (servMgr->UnregisterServiceStatusListener(listener) != 0) {
        DHLOGE("UnregisterServiceStatusListener failed!");
    }
    return DCAMERA_OK;
}

int32_t DCameraHdfOperate::WaitLoadCameraService()
{
    DHLOGI("wait Load camera service.");
    std::unique_lock<std::mutex> lock(hdfOperateMutex_);
    hdfOperateCon_.wait_for(lock, std::chrono::milliseconds(WAIT_TIME), [this] {
        return (this->cameraServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    });

    if (cameraServStatus_.load() != OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
        DHLOGE("wait load cameraService failed, status %{public}d", cameraServStatus_.load());
        return DCAMERA_BAD_OPERATE;
    }

    return DCAMERA_OK;
}

int32_t DCameraHdfOperate::WaitLoadProviderService()
{
    DHLOGI("wait Load provider service.");
    std::unique_lock<std::mutex> lock(hdfOperateMutex_);
    hdfOperateCon_.wait_for(lock, std::chrono::milliseconds(WAIT_TIME), [this] {
        return (this->providerServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
    });

    if (providerServStatus_.load() != OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
        DHLOGE("wait load providerService failed, status %{public}d", providerServStatus_.load());
        return DCAMERA_BAD_OPERATE;
    }

    return DCAMERA_OK;
}

int32_t DCameraHdfOperate::UnLoadDcameraHDFImpl()
{
    DHLOGI("UnLoadCameraHDFImpl begin!");
    OHOS::sptr<IDeviceManager> devmgr = IDeviceManager::Get();
    if (devmgr == nullptr) {
        DHLOGE("get hdi device manager failed!");
        return DCAMERA_BAD_VALUE;
    }

    int32_t ret = devmgr->UnloadDevice(CAMERA_SERVICE_NAME);
    if (ret != 0) {
        DHLOGE("Unload camera service failed, ret: %{public}d", ret);
    }
    ret = devmgr->UnloadDevice(PROVIDER_SERVICE_NAME);
    if (ret != 0) {
        DHLOGE("Unload provider service failed, ret: %d", ret);
    }
    cameraServStatus_.store(INVALID_VALUE);
    providerServStatus_.store(INVALID_VALUE);
    DHLOGI("UnLoadCameraHDFImpl end!");
    return DCAMERA_OK;
}
} // namespace DistributedHardware
} // namespace OHOS
