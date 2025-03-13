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

#ifndef OHOS_DCAMERA_CHANNEL_LISTENER_MOCK_H
#define OHOS_DCAMERA_CHANNEL_LISTENER_MOCK_H

#include <gmock/gmock.h>
#include "icamera_channel_listener.h"

namespace OHOS {
namespace DistributedHardware {

class DCameraChannelListenerMock : public ICameraChannelListener {
public:
    DCameraChannelListenerMock() = default;
    ~DCameraChannelListenerMock() override = default;

    MOCK_METHOD(void, OnSessionState, (int32_t, std::string));
    MOCK_METHOD(void, OnSessionError, (int32_t, int32_t, std::string));
    MOCK_METHOD(void, OnDataReceived, (std::vector<std::shared_ptr<DataBuffer>>&));
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DCAMERA_CHANNEL_LISTENER_MOCK_H
