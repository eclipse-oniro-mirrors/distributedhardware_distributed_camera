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

#ifndef OHOS_DCAMERA_SOURCE_CALLBACK_H
#define OHOS_DCAMERA_SOURCE_CALLBACK_H

#include <map>
#include <mutex>

#include "dcamera_source_callback_stub.h"
#include "idistributed_hardware_source.h"

namespace OHOS {
namespace DistributedHardware {
class DCameraSourceCallback : public DCameraSourceCallbackStub {
public:
    DCameraSourceCallback() = default;
    ~DCameraSourceCallback() override;

    int32_t OnNotifyRegResult(const std::string& devId, const std::string& dhId, const std::string& reqId,
        int32_t status, std::string& data) override;
    int32_t OnNotifyUnregResult(const std::string& devId, const std::string& dhId, const std::string& reqId,
        int32_t status, std::string& data) override;
    int32_t OnHardwareStateChanged(const std::string &devId, const std::string &dhId, int32_t status) override;
    int32_t OnDataSyncTrigger(const std::string &devId) override;

    void PushRegCallback(std::string& reqId, std::shared_ptr<RegisterCallback>& callback);
    void PopRegCallback(std::string& reqId);
    void PushUnregCallback(std::string& reqId, std::shared_ptr<UnregisterCallback>& callback);
    void PopUnregCallback(std::string& reqId);
    void RegisterStateListener(const std::shared_ptr<DistributedHardwareStateListener> listener);
    void UnRegisterStateListener();
    void RegisterTriggerListener(const std::shared_ptr<DataSyncTriggerListener> listener);
    void UnRegisterTriggerListener();
private:
    std::map<std::string, std::shared_ptr<RegisterCallback>> regCallbacks_;
    std::map<std::string, std::shared_ptr<UnregisterCallback>> unregCallbacks_;
    std::mutex mapMutex_;
    std::mutex stateListenerMtx_;
    std::shared_ptr<DistributedHardwareStateListener> stateListener_ = nullptr;
    std::mutex triggerListenerMtx_;
    std::shared_ptr<DataSyncTriggerListener> triggerListener_ = nullptr;
    const size_t DID_MAX_SIZE = 256;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DCAMERA_SOURCE_CALLBACK_H
