/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <securec.h>
#define private public
#include "dcamera_softbus_adapter.h"
#undef private

#include "data_buffer.h"
#include "dcamera_allconnect_manager_test.h"
#include "dcamera_channel_listener_mock.h"
#include "dcamera_softbus_session.h"
#include "dcamera_hisysevent_adapter.h"
#include "dcamera_utils_tools.h"
#include "distributed_camera_constants.h"
#include "distributed_camera_errno.h"
#include "session_bus_center.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::An;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::AtLeast;
using ::testing::InSequence;
using ::testing::SetArgReferee;

namespace OHOS {
namespace DistributedHardware {
class DCameraSoftbusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

namespace {
const std::string TEST_DEVICE_ID = "bb536a637105409e904d4da83790a4a7";
const std::string TEST_CAMERA_DH_ID_0 = "camera_0";
constexpr int32_t UNIQUE_SOCKED_ID = 0;
}

void DCameraSoftbusAdapterTest::SetUpTestCase(void)
{
    DCameraAllConnectManagerTest::InitAllConnectManagerMockEnv();
}

void DCameraSoftbusAdapterTest::TearDownTestCase(void)
{
    DCameraAllConnectManagerTest::UnInitAllConnectManagerMockEnv();
}

void DCameraSoftbusAdapterTest::SetUp(void)
{
}

void DCameraSoftbusAdapterTest::TearDown(void)
{
}

/**
 * @tc.name: dcamera_softbus_adapter_test_001
 * @tc.desc: Verify the CreateSoftbusSessionServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_001, TestSize.Level1)
{
    std::string sessionName = "sourcetest01";
    std::string peerSessionName = "dh_control_0";
    std::string peerDevId = "abcd";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreatSoftBusSinkSocketServer(sessionName, role,
        sessionMode, peerDevId, peerSessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_002
 * @tc.desc: Verify the DestroySoftbusSessionServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_002, TestSize.Level1)
{
    std::string sessionName = "sourcetest02";
    std::string peerSessionName = "dh_control_0";
    std::string peerDevId = "abcd";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreatSoftBusSinkSocketServer(sessionName, role,
        sessionMode, peerDevId, peerSessionName);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_003
 * @tc.desc: Verify the DestroySoftbusSessionServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_003, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreatSoftBusSinkSocketServer(mySessName, role,
        sessionMode, peerDevId, peerSessName);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_004
 * @tc.desc: Verify the DestroySoftbusSessionServer function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_004, TestSize.Level1)
{
    std::string sessionName = "sourcetest04";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest04";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreatSoftBusSinkSocketServer(mySessName, role,
        sessionMode, peerDevId, peerSessName);
    int32_t sessionId = 1;
    ret = DCameraSoftbusAdapter::GetInstance().CloseSoftbusSession(sessionId);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_005
 * @tc.desc: Verify the SendSofbusBytes function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_005, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    size_t capacity = 1;
    std::shared_ptr<DataBuffer> dataBuffer = std::make_shared<DataBuffer>(capacity);
    int32_t sessionId = 2;
    ret = DCameraSoftbusAdapter::GetInstance().SendSofbusBytes(sessionId, dataBuffer);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_006
 * @tc.desc: Verify the SendSofbusStream function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_006, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    size_t capacity = 1;
    std::shared_ptr<DataBuffer> dataBuffer = std::make_shared<DataBuffer>(capacity);
    int32_t sessionId = 2;
    ret = DCameraSoftbusAdapter::GetInstance().SendSofbusStream(sessionId, dataBuffer);
    dataBuffer->SetInt64(TIME_STAMP_US, 1);
    ret = DCameraSoftbusAdapter::GetInstance().SendSofbusStream(sessionId, dataBuffer);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_007
 * @tc.desc: Verify the GetLocalNetworkId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_007, TestSize.Level1)
{
    std::string devId = TEST_DEVICE_ID;
    int32_t ret = DCameraSoftbusAdapter::GetInstance().GetLocalNetworkId(devId);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_008
 * @tc.desc: Verify the OnSourceSessionOpened function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_008, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_009
 * @tc.desc: Verify the OnSourceSessionClosed function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_009, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);

    DCameraSoftbusAdapter::GetInstance().SourceOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_010
 * @tc.desc: Verify the OnSourceBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_010, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    const void *data = "testdata";
    uint32_t dataLen = 8;
    DCameraSoftbusAdapter::GetInstance().SourceOnBytes(sessionId, data, dataLen);
    DCameraSoftbusAdapter::GetInstance().SourceOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_011
 * @tc.desc: Verify the OnSourceBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_011, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    const void *data = "testdata";
    uint32_t dataLen = 8;
    DCameraSoftbusAdapter::GetInstance().SourceOnMessage(sessionId, data, dataLen);
    DCameraSoftbusAdapter::GetInstance().SourceOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_012
 * @tc.desc: Verify the OnSourceBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_012, TestSize.Level1)
{
    std::string sessionName = "sourcetest03";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest03";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    std::string buff01 = "testbuffer01";
    StreamData test01;
    test01.buf = const_cast<char *>(buff01.c_str());
    test01.bufLen = buff01.size();
    StreamData test02;
    std::string buff02 = "testbuffer01";
    test02.buf = const_cast<char *>(buff02.c_str());
    test02.bufLen = buff02.size();
    StreamFrameInfo param01;
    StreamData *data = &test01;
    StreamData *ext = &test02;
    StreamFrameInfo *param = &param01;
    DCameraSoftbusAdapter::GetInstance().SourceOnStream(sessionId, data, ext, param);
    data = nullptr;
    DCameraSoftbusAdapter::GetInstance().SourceOnStream(sessionId, data, ext, param);
    StreamData test03;
    test01.buf = const_cast<char *>(buff01.c_str());
    test01.bufLen = 0;
    data = &test03;
    DCameraSoftbusAdapter::GetInstance().SourceOnStream(sessionId, data, ext, param);
    DCameraSoftbusAdapter::GetInstance().SourceOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_012
 * @tc.desc: Verify the OnSinkSessionOpened function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_013, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    DCameraSoftbusAdapter::GetInstance().sinkSessions_.emplace(peerDevId + mySessName, session);
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}
/**
 * @tc.name: dcamera_softbus_adapter_test_014
 * @tc.desc: Verify the OnSinkSessionClosed function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_014, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    ManageSelectChannel::GetInstance().SetSinkConnect(true);
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_VIDEO_STREAM,
    };
    DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);

    DCameraSoftbusAdapter::GetInstance().SinkOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_015
 * @tc.desc: Verify the OnSinkBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_015, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);
    const void *data = "testdata";
    uint32_t dataLen = 8;
    DCameraSoftbusAdapter::GetInstance().SinkOnBytes(sessionId, data, dataLen);
    DCameraSoftbusAdapter::GetInstance().SinkOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_016
 * @tc.desc: Verify the OnSinkMessageReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_016, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);
    const void *data = "testdata";
    uint32_t dataLen = 8;
    DCameraSoftbusAdapter::GetInstance().SinkOnMessage(sessionId, data, dataLen);
    DCameraSoftbusAdapter::GetInstance().SinkOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_017
 * @tc.desc: Verify the OnSinkStreamReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_017, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);
    std::string buff01 = "testbuffer01";
    StreamData test01;
    test01.buf = const_cast<char *>(buff01.c_str());
    test01.bufLen = buff01.size();
    StreamData test02;
    std::string buff02 = "testbuffer01";
    test02.buf = const_cast<char *>(buff02.c_str());
    test02.bufLen = buff02.size();
    StreamFrameInfo param01;
    const StreamData *data = &test01;
    const StreamData *ext = &test02;
    const StreamFrameInfo *param = &param01;
    DCameraSoftbusAdapter::GetInstance().SinkOnStream(sessionId, data, ext, param);
    DCameraSoftbusAdapter::GetInstance().SinkOnShutDown(sessionId, ShutdownReason::SHUTDOWN_REASON_LOCAL);
    ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_018
 * @tc.desc: Verify the DCameraSoftbusSourceGetSession function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_018, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    ret = DCameraSoftbusAdapter::GetInstance().DCameraSoftbusSourceGetSession(sessionId, session);

    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_019
 * @tc.desc: Verify the DCameraSoftbusSinkGetSession function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_019, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);
    ret = DCameraSoftbusAdapter::GetInstance().DCameraSoftbusSinkGetSession(sessionId, session);

    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_020
 * @tc.desc: Verify the DCameraSoftbusGetSessionById function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_020, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 2;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);

    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_023
 * @tc.desc: Verify the DCameraSoftbusGetSessionById function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_023, TestSize.Level1)
{
    std::string sessionName = "sourcetest013";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest013";
    std::string peerSessName = "sinktest012";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = -1;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(sessionId, info);

    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_027
 * @tc.desc: Verify the DCameraSoftbusSourceGetSession function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_027, TestSize.Level1)
{
    std::string sessionName = "sourcetest027";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest027";
    std::string peerSessName = "sinktest0027";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 27;
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    ret = DCameraSoftbusAdapter::GetInstance().DCameraSoftbusSourceGetSession(sessionId, session);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
    mySessName = "sourcetest0027";
    ret = DCameraSoftbusAdapter::GetInstance().DCameraSoftbusSourceGetSession(sessionId, session);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
    sessionId = 2;
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_028
 * @tc.desc: Verify the OnSourceBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_028, TestSize.Level1)
{
    int32_t sessionId = 2;
    const void *data = "testdata";
    uint32_t dataLen = 0;
    std::string sessionName = "sourcetest028";
    DCameraSoftbusAdapter::GetInstance().SourceOnBytes(sessionId, data, dataLen);
    dataLen = DCAMERA_MAX_RECV_DATA_LEN + 1;
    DCameraSoftbusAdapter::GetInstance().SourceOnBytes(sessionId, data, dataLen);
    dataLen = 8;
    data = nullptr;
    DCameraSoftbusAdapter::GetInstance().SourceOnBytes(sessionId, data, dataLen);
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CloseSoftbusSession(sessionId);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_029
 * @tc.desc: Verify the OnSinkBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_029, TestSize.Level1)
{
    int32_t sessionId = 2;
    const void *data = "testdata";
    uint32_t dataLen = 0;
    std::string sessionName = "sourcetest029";
    DCameraSoftbusAdapter::GetInstance().SinkOnBytes(sessionId, data, dataLen);
    dataLen = DCAMERA_MAX_RECV_DATA_LEN + 1;
    DCameraSoftbusAdapter::GetInstance().SinkOnBytes(sessionId, data, dataLen);
    data = nullptr;
    dataLen = 8;
    DCameraSoftbusAdapter::GetInstance().SinkOnBytes(sessionId, data, dataLen);
    int32_t ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_030
 * @tc.desc: Verify the OnSinkBytesReceived function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_030, TestSize.Level1)
{
    std::string sessionName = "sourcetest030";
    int32_t sessionId = 2;
    std::string buff01 = "testbuffer030";
    StreamData test02;
    std::string buff02 = "testbuffer030";
    test02.buf = const_cast<char *>(buff02.c_str());
    test02.bufLen = buff02.size();
    StreamFrameInfo param01;
    StreamData *data = nullptr;
    StreamData *ext = &test02;
    StreamFrameInfo *param = &param01;
    DCameraSoftbusAdapter::GetInstance().SinkOnStream(sessionId, data, ext, param);
    data = &test02;
    data->bufLen = 0;
    DCameraSoftbusAdapter::GetInstance().SinkOnStream(sessionId, data, ext, param);
    data->bufLen = DCAMERA_MAX_RECV_DATA_LEN + 1;
    DCameraSoftbusAdapter::GetInstance().SinkOnStream(sessionId, data, ext, param);
    int32_t ret = DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_032
 * @tc.desc: Verify the CreateSoftbusSessionServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_032, TestSize.Level1)
{
    size_t capacity = 1;
    std::shared_ptr<DataBuffer> dataBuffer = std::make_shared<DataBuffer>(capacity);
    std::string buff01 = R"({
        "type": 0,
        "index": 1,
        "pts": 1,
        "encodeT": 1,
        "sendT": 1,
        "ver": "test",
    })";
    StreamData test01;
    test01.buf = const_cast<char *>(buff01.c_str());
    test01.bufLen = buff01.size();
    StreamData *data = &test01;
    int32_t ret = DCameraSoftbusAdapter::GetInstance().HandleSourceStreamExt(dataBuffer, data);
    EXPECT_EQ(DCAMERA_BAD_VALUE, ret);

    test01.bufLen = 0;
    ret = DCameraSoftbusAdapter::GetInstance().HandleSourceStreamExt(dataBuffer, data);
    EXPECT_EQ(DCAMERA_BAD_VALUE, ret);

    test01.bufLen = DCAMERA_MAX_RECV_EXT_LEN + 1;
    ret = DCameraSoftbusAdapter::GetInstance().HandleSourceStreamExt(dataBuffer, data);
    EXPECT_EQ(DCAMERA_BAD_VALUE, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_033
 * @tc.desc: Verify the DCameraSoftbusSourceGetSession function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_033, TestSize.Level1)
{
    std::string sessionName = "sourcetest033";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest033";
    std::string peerSessName = "sourcetest033";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    ManageSelectChannel::GetInstance().SetSrcConnect(true);
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    int32_t sessionId = 27;
    std::shared_ptr<DCameraSoftbusSession> session = std::make_shared<DCameraSoftbusSession>();
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(sessionId, info);
    ret = DCameraSoftbusAdapter::GetInstance().DCameraSoftbusSourceGetSession(sessionId, session);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
    mySessName = "sourcetest0027";
    ret = DCameraSoftbusAdapter::GetInstance().DCameraSoftbusSourceGetSession(sessionId, session);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);
    sessionId = 2;
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_NOT_FOUND, ret);

    int32_t socket = 0;
    DCameraSoftbusAdapter::GetInstance().RecordSourceSocketSession(socket, session);

    session = nullptr;
    DCameraSoftbusAdapter::GetInstance().RecordSourceSocketSession(socket, session);
    std::shared_ptr<DataBuffer> buffer = nullptr;
    StreamData *ext = nullptr;
    ret = DCameraSoftbusAdapter::GetInstance().HandleSourceStreamExt(buffer, ext);
    EXPECT_EQ(DCAMERA_BAD_VALUE, ret);
}

/**
 * @tc.name: dcamera_softbus_adapter_test_034
 * @tc.desc: Verify the SendSofbusStream function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DCameraSoftbusAdapterTest, dcamera_softbus_adapter_test_034, TestSize.Level1)
{
    std::string sessionName = "sourcetest034";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest034";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    size_t capacity = 1;
    std::shared_ptr<DataBuffer> dataBuffer = std::make_shared<DataBuffer>(capacity);
    int32_t sessionId = 1;
    dataBuffer->SetInt64(TIME_STAMP_US, 1);
    dataBuffer->SetInt64(FRAME_TYPE, 1);
    dataBuffer->SetInt64(INDEX, 1);
    dataBuffer->SetInt64(START_ENCODE_TIME_US, 0);
    dataBuffer->SetInt64(FINISH_ENCODE_TIME_US, 1);
    ret = DCameraSoftbusAdapter::GetInstance().SendSofbusStream(sessionId, dataBuffer);
    DCameraSoftbusAdapter::GetInstance().DestroySoftbusSessionServer(sessionName);
    EXPECT_EQ(DCAMERA_OK, ret);
}

HWTEST_F(DCameraSoftbusAdapterTest, DCameraSoftbusAdapterTest_035, TestSize.Level1)
{
    DCameraSoftbusAdapter::GetInstance().CloseSessionWithNetWorkId("");
    std::string sessionName = "sourcetest035";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string mySessName = "sourcetest035";
    std::string peerSessName = "sinktest02";
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    std::string peerDevId = TEST_DEVICE_ID;
    std::string myDevId = "abcde";
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);
    DCameraSoftbusAdapter::GetInstance().CloseSessionWithNetWorkId("testNetworkId");
    EXPECT_NE(ret, DCAMERA_BAD_VALUE);
}

HWTEST_F(DCameraSoftbusAdapterTest, DCameraSoftbusAdapterTest_036, TestSize.Level1)
{
    std::string myDevId = "abcde";
    std::string peerSessName = "sink_control";
    std::string peerDevId = TEST_DEVICE_ID;
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_VIDEO;
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNLE_ROLE_SOURCE;
    std::string myDhId = "mydhid";
    int32_t ret = DCameraSoftbusAdapter::GetInstance().CreateSoftBusSourceSocketClient(myDhId, myDevId,
        peerSessName, peerDevId, sessionMode, role);

    DCameraSoftbusAdapter::GetInstance().CloseSessionWithNetWorkId(peerDevId);
    EXPECT_EQ(ret, UNIQUE_SOCKED_ID);
}

HWTEST_F(DCameraSoftbusAdapterTest, DCameraSoftbusAdapterTest_037, TestSize.Level1)
{
    std::string myDevId = "abcde";
    std::string sessionName = "sourcetest037";
    std::string peerDevId = TEST_DEVICE_ID;
    std::string peerSessName = "sink_control";
    std::string dhId = "dhId";

    auto listener = std::make_shared<DCameraChannelListenerMock>();
    auto session = std::make_shared<DCameraSoftbusSession>(
        dhId, myDevId, sessionName, peerDevId, peerSessName, listener, DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL);
    EXPECT_CALL(*listener, OnSessionState(_, _)).Times(AtLeast(1));

    DCameraSoftbusAdapter::GetInstance().RecordSourceSocketSession(UNIQUE_SOCKED_ID, session);
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    auto ret = DCameraSoftbusAdapter::GetInstance().SourceOnBind(UNIQUE_SOCKED_ID, info);

    DCameraSoftbusAdapter::GetInstance().CloseSoftbusSession(UNIQUE_SOCKED_ID);
    DCameraAllConnectManager::RemoveSourceNetworkId(UNIQUE_SOCKED_ID);
    EXPECT_EQ(ret, DCAMERA_OK);
}

HWTEST_F(DCameraSoftbusAdapterTest, DCameraSoftbusAdapterTest_038, TestSize.Level1)
{
    std::string mySessionName = "control";
    DCAMERA_CHANNEL_ROLE role = DCAMERA_CHANNEL_ROLE::DCAMERA_CHANNLE_ROLE_SINK;
    DCameraSessionMode sessionMode = DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL;
    std::string myDevId = "abcde";
    std::string peerDevId = TEST_DEVICE_ID;
    std::string peerSessionName = peerDevId + "_control";
    std::string dhId = "dhId";
    DCameraSoftbusAdapter::GetInstance().mySocketSet_.clear();
    ManageSelectChannel::GetInstance().SetSinkConnect(false);
    DCameraSoftbusAdapter::GetInstance().CreatSoftBusSinkSocketServer(
        mySessionName, role, sessionMode, peerDevId, peerSessionName);
    auto listener = std::make_shared<DCameraChannelListenerMock>();
    EXPECT_CALL(*listener, OnSessionState(_, _)).Times(AtLeast(1));
    auto session = std::make_shared<DCameraSoftbusSession>(
        dhId, myDevId, mySessionName, peerDevId, peerSessionName, listener,
        DCameraSessionMode::DCAMERA_SESSION_MODE_CTRL);
    DCameraSoftbusAdapter::GetInstance().sinkSessions_[mySessionName] = session;
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSessionName.c_str()),
        .pkgName = const_cast<char*>(DCAMERA_PKG_NAME.c_str()),
        .networkId = const_cast<char*>(peerDevId.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    auto ret = DCameraSoftbusAdapter::GetInstance().SinkOnBind(UNIQUE_SOCKED_ID, info);

    DCameraSoftbusAdapter::GetInstance().SinkOnShutDown(UNIQUE_SOCKED_ID, SHUTDOWN_REASON_UNEXPECTED);
    DCameraSoftbusAdapter::GetInstance().CloseSoftbusSession(UNIQUE_SOCKED_ID);
    DCameraSoftbusAdapter::GetInstance().mySocketSet_.erase(UNIQUE_SOCKED_ID);
    DCameraSoftbusAdapter::GetInstance().sinkSessions_.erase(mySessionName);
    EXPECT_EQ(ret, DCAMERA_OK);
}

HWTEST_F(DCameraSoftbusAdapterTest, DCameraSoftbusAdapterTest_039, TestSize.Level1)
{
    std::string networkId = "testNetworkId";
    bool isInvalid = false;
    int32_t typeVal = DCameraSoftbusAdapter::GetInstance().CheckOsType(networkId, isInvalid);
    typeVal = 50;
    std::string jsonStr = "{\"OS_TYPE\": 50}";
    std::string key = "OS_TYPE";
    int32_t result = DCameraSoftbusAdapter::GetInstance().ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, typeVal);

    jsonStr = "invalid_json";
    key = "typeVal";
    result = DCameraSoftbusAdapter::GetInstance().ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, DCAMERA_BAD_VALUE);

    jsonStr = "{\"test\": 80}";
    result = DCameraSoftbusAdapter::GetInstance().ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, DCAMERA_BAD_VALUE);

    jsonStr = "{\"test\": \"typeVal\"}";
    result = DCameraSoftbusAdapter::GetInstance().ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, DCAMERA_BAD_VALUE);

    jsonStr = "";
    result = DCameraSoftbusAdapter::GetInstance().ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, DCAMERA_BAD_VALUE);

    jsonStr = "null";
    key = "typeVal";
    result = DCameraSoftbusAdapter::GetInstance().ParseValueFromCjson(jsonStr, key);
    EXPECT_EQ(result, DCAMERA_BAD_VALUE);
}
}
}
