/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "dcamera_stream_data_process.h"

#include "anonymous_string.h"
#include "distributed_camera_constants.h"
#include "distributed_camera_errno.h"
#include "distributed_hardware_log.h"

#include "dcamera_pipeline_source.h"
#include "dcamera_stream_data_process_pipeline_listener.h"

namespace OHOS {
namespace DistributedHardware {
DCameraStreamDataProcess::DCameraStreamDataProcess(std::string devId, std::string dhId, DCStreamType streamType)
    : devId_(devId), dhId_(dhId), streamType_(streamType)
{
    DHLOGI("DCameraStreamDataProcess Constructor devId %{public}s dhId %{public}s", GetAnonyString(devId_).c_str(),
        GetAnonyString(dhId_).c_str());
    pipeline_ = nullptr;
    listener_ = nullptr;
}

DCameraStreamDataProcess::~DCameraStreamDataProcess()
{
    DHLOGI("DCameraStreamDataProcess Destructor devId %{public}s dhId %{public}s streamType: %{public}d",
        GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_);
    streamIds_.clear();
    producers_.clear();
    if (pipeline_ != nullptr) {
        pipeline_->DestroyDataProcessPipeline();
    }
}

void DCameraStreamDataProcess::FeedStream(std::shared_ptr<DataBuffer>& buffer)
{
    for (auto streamId : streamIds_) {
        uint64_t buffersSize = static_cast<uint64_t>(buffer->Size());
        DHLOGD("FeedStream devId %{public}s dhId %{public}s streamId %{public}d streamType %{public}d streamSize: "
            "%{public}" PRIu64, GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamId,
            streamType_, buffersSize);
    }
    switch (streamType_) {
        case SNAPSHOT_FRAME: {
            FeedStreamToSnapShot(buffer);
            break;
        }
        case CONTINUOUS_FRAME: {
            FeedStreamToContinue(buffer);
            break;
        }
        default:
            break;
    }
}

void DCameraStreamDataProcess::ConfigStreams(std::shared_ptr<DCameraStreamConfig>& dstConfig,
    std::set<int32_t>& streamIds)
{
    for (auto streamId : streamIds) {
        DHLOGI("ConfigStreams devId %{public}s dhId %{public}s streamId %{public}d, width: %{public}d, height: "
            "%{public}d, format: %{public}d, dataspace: %{public}d, encodeType: %{public}d, streamType: %{public}d",
            GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamId, dstConfig->width_,
            dstConfig->height_, dstConfig->format_, dstConfig->dataspace_, dstConfig->encodeType_, dstConfig->type_);
    }
    dstConfig_ = dstConfig;
    streamIds_ = streamIds;
}

void DCameraStreamDataProcess::ReleaseStreams(std::set<int32_t>& streamIds)
{
    for (auto streamId : streamIds) {
        DHLOGI("ReleaseStreams devId %{public}s dhId %{public}s streamId %{public}d streamType %{public}d",
            GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamId, streamType_);
    }
    std::lock_guard<std::mutex> autoLock(producerMutex_);
    for (auto iter = streamIds.begin(); iter != streamIds.end(); iter++) {
        int32_t streamId = *iter;
        DHLOGI("ReleaseStreams devId %{public}s dhId %{public}s streamId: %{public}d", GetAnonyString(devId_).c_str(),
            GetAnonyString(dhId_).c_str(), streamId);
        streamIds_.erase(streamId);
        auto producerIter = producers_.find(streamId);
        if (producerIter == producers_.end()) {
            continue;
        }
        producerIter->second->Stop();
        producers_.erase(streamId);
    }
}

void DCameraStreamDataProcess::StartCapture(std::shared_ptr<DCameraStreamConfig>& srcConfig,
    std::set<int32_t>& streamIds)
{
    for (auto iter = streamIds.begin(); iter != streamIds.end(); iter++) {
        DHLOGI("StartCapture devId %{public}s dhId %{public}s streamType: %{public}d streamId: %{public}d, "
            "srcConfig: width: %{public}d, height: %{public}d, format: %{public}d, dataspace: %{public}d, "
            "streamType: %{public}d, encodeType: %{public}d",
            GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, *iter,
            srcConfig->width_,  srcConfig->height_, srcConfig->format_, srcConfig->dataspace_,
            srcConfig->type_, srcConfig->encodeType_);
    }
    srcConfig_ = srcConfig;
    if (streamType_ == CONTINUOUS_FRAME) {
        CreatePipeline();
    }
    {
        std::lock_guard<std::mutex> autoLock(producerMutex_);
        for (auto iter = streamIds_.begin(); iter != streamIds_.end(); iter++) {
            uint32_t streamId = *iter;
            DHLOGI("StartCapture streamId: %{public}d", streamId);
            if (streamIds.find(streamId) == streamIds.end()) {
                continue;
            }

            DHLOGI("StartCapture findProducer devId %{public}s dhId %{public}s streamType: %{public}d streamId: "
                "%{public}d", GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, streamId);
            auto producerIter = producers_.find(streamId);
            if (producerIter != producers_.end()) {
                continue;
            }
            DHLOGI("StartCapture CreateProducer devId %{public}s dhId %{public}s streamType: %{public}d streamId: "
                "%{public}d", GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, streamId);
            producers_[streamId] =
                std::make_shared<DCameraStreamDataProcessProducer>(devId_, dhId_, streamId, streamType_);
            producers_[streamId]->Start();
        }
    }
}

void DCameraStreamDataProcess::StopCapture(std::set<int32_t>& streamIds)
{
    for (auto iter = streamIds.begin(); iter != streamIds.end(); iter++) {
        DHLOGI("StopCapture devId %{public}s dhId %{public}s streamType: %{public}d streamId: %{public}d",
            GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, *iter);
    }
    {
        std::lock_guard<std::mutex> autoLock(producerMutex_);
        for (auto iter = streamIds_.begin(); iter != streamIds_.end(); iter++) {
            uint32_t streamId = *iter;
            DHLOGI("StopCapture streamId: %{public}d", streamId);
            if (streamIds.find(streamId) == streamIds.end()) {
                continue;
            }

            DHLOGI("StopCapture findProducer devId %{public}s dhId %{public}s streamType: %{public}d streamId: "
                "%{public}d", GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, streamId);
            auto producerIter = producers_.find(streamId);
            if (producerIter == producers_.end()) {
                DHLOGE("StopCapture no producer, devId %{public}s dhId %{public}s streamType: %{public}d streamId: "
                    "%{public}d", GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, streamId);
                continue;
            }
            DHLOGI("StopCapture stop producer, devId %{public}s dhId %{public}s streamType: %{public}d streamId: "
                "%{public}d", GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, streamId);
            producerIter->second->Stop();
            producerIter = producers_.erase(producerIter);
        }
    }
}

void DCameraStreamDataProcess::GetAllStreamIds(std::set<int32_t>& streamIds)
{
    streamIds = streamIds_;
}

int32_t DCameraStreamDataProcess::GetProducerSize()
{
    DHLOGI("DCameraStreamDataProcess GetProducerSize devId %{public}s dhId %{public}s",
        GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str());
    std::lock_guard<std::mutex> autoLock(producerMutex_);
    return producers_.size();
}

void DCameraStreamDataProcess::FeedStreamToSnapShot(const std::shared_ptr<DataBuffer>& buffer)
{
    uint64_t buffersSize = static_cast<uint64_t>(buffer->Size());
    DHLOGD("DCameraStreamDataProcess FeedStreamToSnapShot devId %{public}s dhId %{public}s streamType %{public}d "
        "streamSize: %{public}" PRIu64, GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(),
        streamType_, buffersSize);
    std::lock_guard<std::mutex> autoLock(producerMutex_);
    for (auto iter = producers_.begin(); iter != producers_.end(); iter++) {
        iter->second->FeedStream(buffer);
    }
}

void DCameraStreamDataProcess::FeedStreamToContinue(const std::shared_ptr<DataBuffer>& buffer)
{
    uint64_t buffersSize = static_cast<uint64_t>(buffer->Size());
    DHLOGD("DCameraStreamDataProcess FeedStreamToContinue devId %{public}s dhId %{public}s streamType %{public}d "
        "streamSize: %{public}" PRIu64, GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(),
        streamType_, buffersSize);
    std::lock_guard<std::mutex> autoLock(pipelineMutex_);
    std::vector<std::shared_ptr<DataBuffer>> buffers;
    buffers.push_back(buffer);
    if (pipeline_ == nullptr) {
        buffersSize = static_cast<uint64_t>(buffer->Size());
        DHLOGE("pipeline null devId %{public}s dhId %{public}s type: %{public}d streamSize: %{public}" PRIu64,
            GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(), streamType_, buffersSize);
        return;
    }
    int32_t ret = pipeline_->ProcessData(buffers);
    if (ret != DCAMERA_OK) {
        DHLOGE("pipeline ProcessData failed, ret: %{public}d", ret);
    }
}

void DCameraStreamDataProcess::OnProcessedVideoBuffer(const std::shared_ptr<DataBuffer>& videoResult)
{
    uint64_t resultSize = static_cast<uint64_t>(videoResult->Size());
    DHLOGI("DCameraStreamDataProcess OnProcessedVideoBuffer devId %{public}s dhId %{public}s streamType: %{public}d "
        "streamSize: %{public}" PRIu64, GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str(),
        streamType_, resultSize);
    std::lock_guard<std::mutex> autoLock(producerMutex_);
    for (auto iter = producers_.begin(); iter != producers_.end(); iter++) {
        iter->second->FeedStream(videoResult);
    }
}

void DCameraStreamDataProcess::OnError(const DataProcessErrorType errorType)
{
    DHLOGE("DCameraStreamDataProcess OnError pipeline errorType: %{public}d", errorType);
}

void DCameraStreamDataProcess::CreatePipeline()
{
    DHLOGI("DCameraStreamDataProcess CreatePipeline devId %{public}s dhId %{public}s",
        GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str());
    std::lock_guard<std::mutex> autoLock(pipelineMutex_);
    if (pipeline_ != nullptr) {
        DHLOGI("DCameraStreamDataProcess CreatePipeline already exist, devId %{public}s dhId %{public}s",
            GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str());
        return;
    }
    pipeline_ = std::make_shared<DCameraPipelineSource>();
    auto process = std::shared_ptr<DCameraStreamDataProcess>(shared_from_this());
    listener_ = std::make_shared<DCameraStreamDataProcessPipelineListener>(process);
    VideoConfigParams srcParams(GetPipelineCodecType(srcConfig_->encodeType_), GetPipelineFormat(srcConfig_->format_),
        DCAMERA_PRODUCER_FPS_DEFAULT, srcConfig_->width_, srcConfig_->height_);
    VideoConfigParams dstParams(GetPipelineCodecType(dstConfig_->encodeType_), GetPipelineFormat(dstConfig_->format_),
        DCAMERA_PRODUCER_FPS_DEFAULT, dstConfig_->width_, dstConfig_->height_);
    int32_t ret = pipeline_->CreateDataProcessPipeline(PipelineType::VIDEO, srcParams, dstParams, listener_);
    if (ret != DCAMERA_OK) {
        DHLOGE("DCameraStreamDataProcess CreateDataProcessPipeline type: %{public}d failed, ret: %{public}d",
            PipelineType::VIDEO, ret);
    }
}

void DCameraStreamDataProcess::DestroyPipeline()
{
    DHLOGI("DCameraStreamDataProcess DestroyPipeline devId %{public}s dhId %{public}s",
        GetAnonyString(devId_).c_str(), GetAnonyString(dhId_).c_str());
    std::lock_guard<std::mutex> autoLock(pipelineMutex_);
    if (pipeline_ == nullptr) {
        return;
    }
    pipeline_->DestroyDataProcessPipeline();
    pipeline_ = nullptr;
}

VideoCodecType DCameraStreamDataProcess::GetPipelineCodecType(DCEncodeType encodeType)
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

Videoformat DCameraStreamDataProcess::GetPipelineFormat(int32_t format)
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
} // namespace DistributedHardware
} // namespace OHOS
