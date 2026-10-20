/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "stream_metrics.h"

#include <chrono>

StreamMetrics &StreamMetrics::GetInstance()
{
    static StreamMetrics instance;
    return instance;
}

int64_t StreamMetrics::GetNowMs() const
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

void StreamMetrics::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    data_ = StreamMetricsData{};
}

void StreamMetrics::MarkSwitchStart()
{
    std::lock_guard<std::mutex> lock(mutex_);
    data_.switchStartMs = GetNowMs();
    data_.switchEndMs = 0;
    data_.firstFrameMs = 0;
    data_.frameCount = 0;
    data_.switchSuccess = false;
}

void StreamMetrics::MarkFirstFrame()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (data_.firstFrameMs == 0 && data_.switchStartMs > 0) {
        data_.firstFrameMs = GetNowMs() - data_.switchStartMs;
    }
    data_.frameCount++;
}

void StreamMetrics::MarkSwitchEnd(bool success)
{
    std::lock_guard<std::mutex> lock(mutex_);
    data_.switchEndMs = GetNowMs();
    data_.switchSuccess = success;
    if (data_.firstFrameMs == 0 && success) {
        data_.firstFrameMs = data_.switchEndMs - data_.switchStartMs;
    }
}

void StreamMetrics::MarkAudioPulse()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (data_.switchStartMs > 0) {
        data_.audioPulseMs = GetNowMs() - data_.switchStartMs;
    }
}

StreamMetricsData StreamMetrics::GetMetrics() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return data_;
}

