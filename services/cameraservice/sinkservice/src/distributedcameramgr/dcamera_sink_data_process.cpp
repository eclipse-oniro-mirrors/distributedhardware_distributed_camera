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

#include "dcamera_sink_data_process.h"

#include "anonymous_string.h"
#include "dcamera_channel_sink_impl.h"
#include "dcamera_pipeline_sink.h"
#include "dcamera_sink_data_process_listener.h"
#include "dcamera_hidumper.h"
#include "dcamera_utils_tools.h"
#include "distributed_camera_constants.h"
#include "distributed_camera_errno.h"
#include "distributed_hardware_log.h"
#include <sys/prctl.h>

namespace OHOS {
namespace DistributedHardware {
DCameraSinkDataProcess::DCameraSinkDataProcess(const std::string& dhId, std::shared_ptr<ICameraChannel>& channel)
    : dhId_(dhId), channel_(channel), eventHandler_(nullptr)
{
    DHLOGI("DCameraSinkDataProcess Constructor dhId: %{public}s", GetAnonyString(dhId_).c_str());
}

DCameraSinkDataProcess::~DCameraSinkDataProcess()
{
    DHLOGI("DCameraSinkDataProcess delete dhId: %{public}s", GetAnonyString(dhId_).c_str());
    if ((eventHandler_ != nullptr) && (eventHandler_->GetEventRunner() != nullptr)) {
        eventHandler_->GetEventRunner()->Stop();
    }
    eventThread_.join();
    eventHandler_ = nullptr;
}

void DCameraSinkDataProcess::Init()
{
    DHLOGI("DCameraSinkDataProcess Init dhId: %{public}s", GetAnonyString(dhId_).c_str());
    eventThread_ = std::thread(&DCameraSinkDataProcess::StartEventHandler, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
}

void DCameraSinkDataProcess::StartEventHandler()
{
    prctl(PR_SET_NAME, SINK_START_EVENT.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
}

int32_t DCameraSinkDataProcess::StartCapture(std::shared_ptr<DCameraCaptureInfo>& captureInfo)
{
    DHLOGI("StartCapture dhId: %{public}s, width: %{public}d, height: %{public}d, format: %{public}d, stream: "
        "%{public}d, encode: %{public}d", GetAnonyString(dhId_).c_str(), captureInfo->width_, captureInfo->height_,
        captureInfo->format_, captureInfo->streamType_, captureInfo->encodeType_);
    captureInfo_ = captureInfo;
    if (pipeline_ != nullptr) {
        DHLOGI("StartCapture %{public}s pipeline already exits", GetAnonyString(dhId_).c_str());
        return DCAMERA_OK;
    }

    if (captureInfo->streamType_ == CONTINUOUS_FRAME) {
        DHLOGI("StartCapture %{public}s create data process pipeline", GetAnonyString(dhId_).c_str());
        pipeline_ = std::make_shared<DCameraPipelineSink>();
        auto dataProcess = std::shared_ptr<DCameraSinkDataProcess>(shared_from_this());
        std::shared_ptr<DataProcessListener> listener = std::make_shared<DCameraSinkDataProcessListener>(dataProcess);
        VideoConfigParams srcParams(VideoCodecType::NO_CODEC,
                                    GetPipelineFormat(captureInfo->format_),
                                    DCAMERA_PRODUCER_FPS_DEFAULT,
                                    captureInfo->width_,
                                    captureInfo->height_);
        VideoConfigParams destParams(GetPipelineCodecType(captureInfo->encodeType_),
                                     GetPipelineFormat(captureInfo->format_),
                                     DCAMERA_PRODUCER_FPS_DEFAULT,
                                     captureInfo->width_,
                                     captureInfo->height_);
        int32_t ret = pipeline_->CreateDataProcessPipeline(PipelineType::VIDEO, srcParams, destParams, listener);
        if (ret != DCAMERA_OK) {
            DHLOGE("create data process pipeline failed, dhId: %{public}s, ret: %{public}d",
                   GetAnonyString(dhId_).c_str(), ret);
            return ret;
        }
    }
    DHLOGI("StartCapture %{public}s success", GetAnonyString(dhId_).c_str());
    return DCAMERA_OK;
}

int32_t DCameraSinkDataProcess::StopCapture()
{
    DHLOGI("StopCapture dhId: %{public}s", GetAnonyString(dhId_).c_str());
    if (pipeline_ != nullptr) {
        pipeline_->DestroyDataProcessPipeline();
        pipeline_ = nullptr;
    }
    if (eventHandler_ != nullptr) {
        DHLOGI("StopCapture dhId: %{public}s, remove all events", GetAnonyString(dhId_).c_str());
        eventHandler_->RemoveAllEvents();
    }
    return DCAMERA_OK;
}

int32_t DCameraSinkDataProcess::FeedStream(std::shared_ptr<DataBuffer>& dataBuffer)
{
    DCStreamType type = captureInfo_->streamType_;
    DHLOGD("FeedStream dhId: %{public}s, stream type: %{public}d", GetAnonyString(dhId_).c_str(), type);
    switch (type) {
        case CONTINUOUS_FRAME: {
            int32_t ret = FeedStreamInner(dataBuffer);
            if (ret != DCAMERA_OK) {
                DHLOGE("FeedStream continuous frame failed, dhId: %{public}s, ret: %{public}d",
                    GetAnonyString(dhId_).c_str(), ret);
                return ret;
            }
            break;
        }
        case SNAPSHOT_FRAME: {
            SendDataAsync(dataBuffer);
            break;
        }
        default: {
            DHLOGE("FeedStream %{public}s unknown stream type: %{public}d", GetAnonyString(dhId_).c_str(), type);
            break;
        }
    }
    return DCAMERA_OK;
}

void DCameraSinkDataProcess::SendDataAsync(const std::shared_ptr<DataBuffer>& buffer)
{
    auto sendFunc = [this, buffer]() mutable {
        std::shared_ptr<DataBuffer> sendBuffer = buffer;
        int32_t ret = channel_->SendData(sendBuffer);
        uint64_t buffersSize = static_cast<uint64_t>(buffer->Size());
        DHLOGD("SendData type: %{public}d output data ret: %{public}d, dhId: %{public}s, bufferSize: %{public}" PRIu64,
            captureInfo_->streamType_, ret, GetAnonyString(dhId_).c_str(), buffersSize);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(sendFunc);
    }
}

void DCameraSinkDataProcess::OnProcessedVideoBuffer(const std::shared_ptr<DataBuffer>& videoResult)
{
#ifdef DUMP_DCAMERA_FILE
    if (DcameraHidumper::GetInstance().GetDumpFlag() && (IsUnderDumpMaxSize(DUMP_PATH + AFTER_ENCODE) == DCAMERA_OK)) {
        DumpBufferToFile(DUMP_PATH + AFTER_ENCODE, videoResult->Data(), videoResult->Size());
    }
#endif
    SendDataAsync(videoResult);
}

void DCameraSinkDataProcess::OnError(DataProcessErrorType errorType)
{
    DHLOGE("OnError %{public}s data process pipeline error, errorType: %{public}d",
           GetAnonyString(dhId_).c_str(), errorType);
}

int32_t DCameraSinkDataProcess::FeedStreamInner(std::shared_ptr<DataBuffer>& dataBuffer)
{
    std::vector<std::shared_ptr<DataBuffer>> buffers;
    buffers.push_back(dataBuffer);
    int32_t ret = pipeline_->ProcessData(buffers);
    if (ret != DCAMERA_OK) {
        DHLOGE("process data failed, dhId: %{public}s, ret: %{public}d", GetAnonyString(dhId_).c_str(), ret);
        return ret;
    }
    return DCAMERA_OK;
}

VideoCodecType DCameraSinkDataProcess::GetPipelineCodecType(DCEncodeType encodeType)
{
    VideoCodecType codecType;
    switch (encodeType) {
        case ENCODE_TYPE_H264:
            codecType = VideoCodecType::CODEC_H264;
            break;
        case ENCODE_TYPE_H265:
            codecType = VideoCodecType::CODEC_H265;
            break;
        case ENCODE_TYPE_MPEG4_ES:
            codecType = VideoCodecType::CODEC_MPEG4_ES;
            break;
        default:
            codecType = VideoCodecType::NO_CODEC;
            break;
    }
    return codecType;
}

Videoformat DCameraSinkDataProcess::GetPipelineFormat(int32_t format)
{
    Videoformat videoFormat;
    switch (format) {
        case OHOS_CAMERA_FORMAT_RGBA_8888:
            videoFormat = Videoformat::RGBA_8888;
            break;
        default:
            videoFormat = Videoformat::NV21;
            break;
    }
    return videoFormat;
}

int32_t DCameraSinkDataProcess::GetProperty(const std::string& propertyName, PropertyCarrier& propertyCarrier)
{
    if (pipeline_ == nullptr) {
        DHLOGD("GetProperty: pipeline is nullptr.");
        return DCAMERA_BAD_VALUE;
    }
    return pipeline_->GetProperty(propertyName, propertyCarrier);
}
} // namespace DistributedHardware
} // namespace OHOS