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

#include <gtest/gtest.h>

#include "dcamera_hdf_operate.h"
#include "distributed_camera_source_service.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
int32_t DistributedHardwareFwkKit::LoadDistributedHDF(const DHType dhType)
{
    return DCameraHdfOperate::GetInstance().LoadDcameraHDFImpl();
}

int32_t DistributedHardwareFwkKit::UnLoadDistributedHDF(const DHType dhType)
{
    return DCameraHdfOperate::GetInstance().UnLoadDcameraHDFImpl();
}
} // DistributedHardware
} // OHOS
