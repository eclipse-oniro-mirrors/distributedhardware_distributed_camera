/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "dcamera_utils_tools.h"

#include <chrono>
#include <dlfcn.h>
#include <string>
#include <sstream>
#include <ostream>

#include "distributed_camera_constants.h"
#include "distributed_camera_errno.h"
#include "distributed_hardware_log.h"
#include "parameter.h"

#include "softbus_bus_center.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const std::string YUV_LIB_PATH = "libyuv.z.so";
const std::string GET_IMAGE_CONVERTER_FUNC = "GetImageConverter";
}

#ifdef DCAMERA_MMAP_RESERVE
using GetImageConverterFunc = OHOS::OpenSourceLibyuv::ImageConverter (*)();
#endif

const uint32_t OFFSET2 = 2;
const uint32_t OFFSET4 = 4;
const uint32_t OFFSET6 = 6;
const uint8_t PARAM_FC = 0xfc;
const uint8_t PARAM_03 = 0x03;
const uint8_t PARAM_F0 = 0xf0;
const uint8_t PARAM_0F = 0x0f;
const uint8_t PARAM_C0 = 0xc0;
const uint8_t PARAM_3F = 0x3f;
const int INDEX_FIRST = 0;
const int INDEX_SECOND = 1;
const int INDEX_THIRD = 2;
const int INDEX_FORTH = 3;
int32_t GetLocalDeviceNetworkId(std::string& networkId)
{
    NodeBasicInfo basicInfo = { { 0 } };
    int32_t ret = GetLocalNodeDeviceInfo(DCAMERA_PKG_NAME.c_str(), &basicInfo);
    if (ret != DCAMERA_OK) {
        DHLOGE("GetLocalNodeDeviceInfo failed ret: %{public}d", ret);
        return ret;
    }

    networkId = std::string(basicInfo.networkId);
    return DCAMERA_OK;
}

int64_t GetNowTimeStampMs()
{
    std::chrono::milliseconds nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return nowMs.count();
}

int64_t GetNowTimeStampUs()
{
    std::chrono::microseconds nowUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
}

int32_t GetAlignedHeight(int32_t width)
{
    int32_t alignedBits = 32;
    int32_t alignedHeight = width;
    if (alignedHeight % alignedBits != 0) {
        alignedHeight = ((alignedHeight / alignedBits) + 1) * alignedBits;
    }
    return alignedHeight;
}

std::string Base64Encode(const unsigned char *toEncode, unsigned int len)
{
    std::string ret = "";
    if (len == 0 || toEncode == nullptr) {
        DHLOGE("toEncode is null or len is zero.");
        return ret;
    }
    int32_t length = static_cast<int32_t>(len);
    uint32_t i = 0;
    unsigned char charArray3[3];
    unsigned char charArray4[4];

    while (length--) {
        charArray3[i++] = *(toEncode++);
        if (i == sizeof(charArray3)) {
            charArray4[INDEX_FIRST] = (charArray3[INDEX_FIRST] & PARAM_FC) >> OFFSET2;
            charArray4[INDEX_SECOND] = ((charArray3[INDEX_FIRST] & PARAM_03) << OFFSET4) +
                ((charArray3[INDEX_SECOND] & PARAM_F0) >> OFFSET4);
            charArray4[INDEX_THIRD] = ((charArray3[INDEX_SECOND] & PARAM_0F) << OFFSET2) +
                ((charArray3[INDEX_THIRD] & PARAM_C0) >> OFFSET6);
            charArray4[INDEX_FORTH] = charArray3[INDEX_THIRD] & PARAM_3F;
            for (i = 0; i < sizeof(charArray4); i++) {
                ret += BASE_64_CHARS[charArray4[i]];
            }
            i = 0;
        }
    }

    if (i > 0) {
        uint32_t j = 0;
        for (j = i; j < sizeof(charArray3); j++) {
            charArray3[j] = '\0';
        }
        charArray4[INDEX_FIRST] = (charArray3[INDEX_FIRST] & PARAM_FC) >> OFFSET2;
        charArray4[INDEX_SECOND] = ((charArray3[INDEX_FIRST] & PARAM_03) << OFFSET4) +
            ((charArray3[INDEX_SECOND] & PARAM_F0) >> OFFSET4);
        charArray4[INDEX_THIRD] = ((charArray3[INDEX_SECOND] & PARAM_0F) << OFFSET2) +
            ((charArray3[INDEX_THIRD] & PARAM_C0) >> OFFSET6);
        charArray4[INDEX_FORTH] = charArray3[INDEX_THIRD] & PARAM_3F;
        for (j = 0; j < i + 1; j++) {
            ret += BASE_64_CHARS[charArray4[j]];
        }
        while (i++ < sizeof(charArray3)) {
            ret += '=';
        }
    }
    return ret;
}

std::string Base64Decode(const std::string& basicString)
{
    std::string ret = "";
    if (basicString.empty()) {
        DHLOGE("basicString is empty.");
        return ret;
    }
    uint32_t i = 0;
    int index = 0;
    int len = static_cast<int>(basicString.size());
    unsigned char charArray3[3];
    unsigned char charArray4[4];

    while (len-- && (basicString[index] != '=') && IsBase64(basicString[index])) {
        charArray4[i++] = basicString[index];
        index++;
        if (i == sizeof(charArray4)) {
            for (i = 0; i < sizeof(charArray4); i++) {
                charArray4[i] = BASE_64_CHARS.find(charArray4[i]);
            }
            charArray3[INDEX_FIRST] = (charArray4[INDEX_FIRST] << OFFSET2) +
                ((charArray4[INDEX_SECOND] & 0x30) >> OFFSET4);
            charArray3[INDEX_SECOND] = ((charArray4[INDEX_SECOND] & 0xf) << OFFSET4) +
                ((charArray4[INDEX_THIRD] & 0x3c) >> OFFSET2);
            charArray3[INDEX_THIRD] = ((charArray4[INDEX_THIRD] & 0x3) << OFFSET6) + charArray4[INDEX_FORTH];
            for (i = 0; i < sizeof(charArray3); i++) {
                ret += charArray3[i];
            }
            i = 0;
        }
    }

    if (i > 0) {
        uint32_t j = 0;
        for (j = i; j < sizeof(charArray4); j++) {
            charArray4[j] = 0;
        }
        for (j = 0; j < sizeof(charArray4); j++) {
            charArray4[j] = BASE_64_CHARS.find(charArray4[j]);
        }
        charArray3[INDEX_FIRST] = (charArray4[INDEX_FIRST] << OFFSET2) +
            ((charArray4[INDEX_SECOND] & 0x30) >> OFFSET4);
        charArray3[INDEX_SECOND] = ((charArray4[INDEX_SECOND] & 0xf) << OFFSET4) +
            ((charArray4[INDEX_THIRD] & 0x3c) >> OFFSET2);
        charArray3[INDEX_THIRD] = ((charArray4[INDEX_THIRD] & 0x3) << OFFSET6) + charArray4[INDEX_FORTH];
        for (j = 0; j < i - 1; j++) {
            ret += charArray3[j];
        }
    }
    return ret;
}

bool IsBase64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

void DumpBufferToFile(const std::string fileName, uint8_t *buffer, size_t bufSize)
{
    if (fileName.empty() || buffer == nullptr) {
        DHLOGE("dumpsaving : input param err.");
        return;
    }
    char path[PATH_MAX + 1] = {0x00};
    if (fileName.length() > PATH_MAX || realpath(fileName.c_str(), path) == nullptr) {
        DHLOGE("The file path is invalid.");
        return;
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::out | std::ios::app);
    if (!ofs.is_open()) {
        DHLOGE("dumpsaving : open file failed.");
        return;
    }
    ofs.write(reinterpret_cast<const char*>(buffer), bufSize);
    ofs.close();
    return;
}

int32_t IsUnderDumpMaxSize(const std::string fileName)
{
    if (fileName.empty()) {
        DHLOGE("dumpsaving : input fileName empty.");
        return DCAMERA_INIT_ERR;
    }
    char path[PATH_MAX + 1] = {0x00};
    if (fileName.length() > PATH_MAX || realpath(fileName.c_str(), path) == nullptr) {
        DHLOGE("The file path is invalid.");
        return DCAMERA_INIT_ERR;
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::out | std::ios::app);
    if (!ofs.is_open()) {
        DHLOGE("dumpsaving : open file failed.");
        return DCAMERA_INIT_ERR;
    }
    ofs.seekp(0, std::ios::end);
    std::ofstream::pos_type fileSize = ofs.tellp();
    if (fileSize < 0) {
        DHLOGE("filesize get err");
        fileSize = 0;
        return DCAMERA_INIT_ERR;
    }
    ofs.close();
    if (static_cast<int32_t>(fileSize) <= DUMP_FILE_MAX_SIZE) {
        return DCAMERA_OK;
    } else {
        return DCAMERA_BAD_VALUE;
    }
}

#ifdef DCAMERA_MMAP_RESERVE
IMPLEMENT_SINGLE_INSTANCE(ConverterHandle);
void ConverterHandle::InitConverter()
{
    dlHandler_ = dlopen(YUV_LIB_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (dlHandler_ == nullptr) {
        DHLOGE("Dlopen failed.");
        return;
    }
    GetImageConverterFunc getConverter = (GetImageConverterFunc)dlsym(dlHandler_, GET_IMAGE_CONVERTER_FUNC.c_str());
    if (getConverter == nullptr) {
        DHLOGE("Function of converter is null, failed reason: %s.", dlerror());
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
        return;
    }
    converter_ = getConverter();
    isInited_.store(true);
    DHLOGI("Initialize image converter success.");
}

void ConverterHandle::DeInitConverter()
{
    if (dlHandler_) {
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
    }
    isInited_.store(false);
}

const OHOS::OpenSourceLibyuv::ImageConverter& ConverterHandle::GetHandle()
{
    if (!isInited_.load()) {
        InitConverter();
    }
    return converter_;
}
#endif

template <typename T>
bool GetSysPara(const char *key, T &value)
{
    CHECK_AND_RETURN_RET_LOG(key == nullptr, false, "key is nullptr");
    char paraValue[30] = {0}; // 30 for system parameter
    auto res = GetParameter(key, "-1", paraValue, sizeof(paraValue));

    CHECK_AND_RETURN_RET_LOG(res <= 0, false, "GetParameter fail, key:%{public}s res:%{public}d", key, res);
    DHLOGD("GetSysPara key:%{public}s value:%{public}s", key, paraValue);
    std::stringstream valueStr;
    valueStr << paraValue;
    valueStr >> value;
    return true;
}

template bool GetSysPara(const char *key, int32_t &value);
template bool GetSysPara(const char *key, uint32_t &value);
template bool GetSysPara(const char *key, int64_t &value);
template bool GetSysPara(const char *key, std::string &value);

std::map<std::string, std::string> DumpFileUtil::g_lastPara = {};

FILE *DumpFileUtil::OpenDumpFileInner(std::string para, std::string fileName)
{
    std::string filePath = DUMP_SERVICE_DIR + fileName;
    std::string dumpPara;
    FILE *dumpFile = nullptr;
    char path[PATH_MAX + 1] = {0x00};
    if (filePath.length() > PATH_MAX || realpath(filePath.c_str(), path) == nullptr) {
        DHLOGE("The file path is invalid.");
        return dumpFile;
    }
    bool res = GetSysPara(para.c_str(), dumpPara);
    if (!res || dumpPara.empty()) {
        DHLOGI("%{public}s is not set, dump dcamera is not required", para.c_str());
        g_lastPara[para] = dumpPara;
        return dumpFile;
    }

    if (dumpPara == "w") {
        dumpFile = fopen(path, "wb+");
        CHECK_AND_RETURN_RET_LOG(dumpFile == nullptr, dumpFile, "Error opening dump file!");
    } else if (dumpPara == "a") {
        dumpFile = fopen(path, "ab+");
        CHECK_AND_RETURN_RET_LOG(dumpFile == nullptr, dumpFile, "Error opening dump file!");
    }
    g_lastPara[para] = dumpPara;
    return dumpFile;
}

void DumpFileUtil::WriteDumpFile(FILE *dumpFile, void *buffer, size_t bufferSize)
{
    if (dumpFile == nullptr) {
        return;
    }
    CHECK_AND_RETURN_LOG(buffer == nullptr, "Invalid write param");
    size_t writeResult = fwrite(buffer, 1, bufferSize, dumpFile);
    CHECK_AND_RETURN_LOG(writeResult != bufferSize, "Failed to write the file.");
}

void DumpFileUtil::CloseDumpFile(FILE **dumpFile)
{
    if (*dumpFile) {
        fclose(*dumpFile);
        *dumpFile = nullptr;
    }
}

void DumpFileUtil::ChangeDumpFileState(std::string para, FILE **dumpFile, std::string filePath)
{
    CHECK_AND_RETURN_LOG(*dumpFile == nullptr, "Invalid file para");
    CHECK_AND_RETURN_LOG(g_lastPara[para] != "w" || g_lastPara[para] != "a", "Invalid input para");
    std::string dumpPara;
    bool res = GetSysPara(para.c_str(), dumpPara);
    if (!res || dumpPara.empty()) {
        DHLOGE("get %{public}s fail", para.c_str());
    }
    if (g_lastPara[para] == "w" && dumpPara == "w") {
        return;
    }
    CloseDumpFile(dumpFile);
    OpenDumpFile(para, filePath, dumpFile);
}

void DumpFileUtil::OpenDumpFile(std::string para, std::string fileName, FILE **file)
{
    if (*file != nullptr) {
        DumpFileUtil::ChangeDumpFileState(para, file, fileName);
        return;
    }

    if (para == DUMP_SERVER_PARA) {
        *file = DumpFileUtil::OpenDumpFileInner(para, fileName);
    }
}

IMPLEMENT_SINGLE_INSTANCE(ManageSelectChannel);
void ManageSelectChannel::SetSrcConnect(bool isSoftbusConnect)
{
    isSoftbusConnectSource_ = isSoftbusConnect;
}

void ManageSelectChannel::SetSinkConnect(bool isSoftbusConnect)
{
    isSoftbusConnectSink_ = isSoftbusConnect;
}

bool ManageSelectChannel::GetSrcConnect()
{
    return isSoftbusConnectSource_;
}

bool ManageSelectChannel::GetSinkConnect()
{
    return isSoftbusConnectSink_;
}
} // namespace DistributedHardware
} // namespace OHOS
