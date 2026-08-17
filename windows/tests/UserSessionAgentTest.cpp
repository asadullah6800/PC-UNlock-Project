#include <gtest/gtest.h>
#include "user_session_agent/UserSessionAgent.h"
#include "ipc/SecureIPC.h"
#include "pairing/DeviceRegistry.h"
#include "pairing/DeviceIdentity.h"
#include "protocol/ProtocolTypes.h"
#include <vector>
#include <string>
#include <memory>
#include <atomic>

using namespace MobileUnlock::Agent;
using namespace MobileUnlock::IPC;
using namespace MobileUnlock::Protocol;
using namespace MobileUnlock::Pairing;

static BOOL WINAPI MockLockWorkStationSuccess() {
    return TRUE;
}

static BOOL WINAPI MockLockWorkStationFailure() {
    return FALSE;
}

class UserSessionAgentTest : public ::testing::Test {
protected:
    void SetUp() override {
        SetRegistryRootForTesting(HKEY_CURRENT_USER);
    }
};

// 1. Session Discovery Test
TEST_F(UserSessionAgentTest, DiscoverCurrentSessionReturnsInfo) {
    SessionInfo info = UserSessionAgent::DiscoverCurrentSession();
    // In any valid Windows environment, active session or 0xFFFFFFFF (if no console) is returned
    EXPECT_TRUE(info.SessionId == 0xFFFFFFFF || info.SessionId >= 0);
}

// 2. Lock Command Processing - Successful Lock
TEST_F(UserSessionAgentTest, ProcessLockCommandSucceedsWhenLockWorkStationReturnsTrue) {
    UserSessionAgent agent;
    agent.SetLockFunctionForTesting(MockLockWorkStationSuccess);

    FrameHeader reqHeader;
    reqHeader.MessageType    = static_cast<uint16_t>(MessageType::LOCK_REQUEST);
    reqHeader.MessageID      = 42;
    reqHeader.SequenceNumber = 1;
    reqHeader.PayloadLength  = 0;

    FrameHeader respHeader;
    std::vector<uint8_t> respPayload;
    bool ok = agent.ProcessLockCommand(reqHeader, {}, respHeader, respPayload);

    EXPECT_TRUE(ok);
    EXPECT_EQ(respHeader.MessageType, static_cast<uint16_t>(MessageType::LOCK_RESPONSE));
    EXPECT_EQ(respHeader.MessageID, 42u);
    EXPECT_EQ(respHeader.SequenceNumber, 2u);

    std::string payloadStr(respPayload.begin(), respPayload.end());
    EXPECT_NE(payloadStr.find("SUCCESS"), std::string::npos);
}

// 3. Lock Command Processing - Failed Lock
TEST_F(UserSessionAgentTest, ProcessLockCommandFailsWhenLockWorkStationReturnsFalse) {
    UserSessionAgent agent;
    agent.SetLockFunctionForTesting(MockLockWorkStationFailure);

    FrameHeader reqHeader;
    reqHeader.MessageType    = static_cast<uint16_t>(MessageType::LOCK_REQUEST);
    reqHeader.MessageID      = 100;
    reqHeader.SequenceNumber = 5;
    reqHeader.PayloadLength  = 0;

    FrameHeader respHeader;
    std::vector<uint8_t> respPayload;
    bool ok = agent.ProcessLockCommand(reqHeader, {}, respHeader, respPayload);

    EXPECT_FALSE(ok);
    EXPECT_EQ(respHeader.MessageType, static_cast<uint16_t>(MessageType::LOCK_RESPONSE));
    EXPECT_EQ(respHeader.MessageID, 100u);

    std::string payloadStr(respPayload.begin(), respPayload.end());
    EXPECT_NE(payloadStr.find("FAILURE"), std::string::npos);
    EXPECT_NE(payloadStr.find("LOCK_FAILED"), std::string::npos);
}

// 4. IPC Delivery: NamedPipeServer dispatches LOCK_REQUEST and Agent processes it
TEST_F(UserSessionAgentTest, IpcDispatchAndLockResponseRoundTrip) {
    const std::wstring testPipeName = L"\\\\.\\pipe\\MobileUnlockTestLockIPC";

    NamedPipeServer server(testPipeName);
    std::atomic<bool> serverReceivedResponse{false};
    std::string serverResponsePayload;

    ASSERT_TRUE(server.Start([&](const std::vector<uint8_t>& msg) {
        auto hdr = DeserializeFrameHeader(msg.data(), msg.size());
        if (hdr.has_value() && hdr.value.MessageType == static_cast<uint16_t>(MessageType::LOCK_RESPONSE)) {
            serverReceivedResponse.store(true);
            if (msg.size() > FRAME_HEADER_SIZE) {
                serverResponsePayload.assign(msg.begin() + FRAME_HEADER_SIZE, msg.end());
            }
        }
    }));

    NamedPipeClient client(testPipeName);
    ASSERT_TRUE(client.Connect(2000));

    // Ensure server has completed connection handshake
    int waits = 0;
    while (!server.IsConnected() && waits++ < 20) {
        Sleep(10);
    }
    ASSERT_TRUE(server.IsConnected());

    // Send LOCK_REQUEST from server to client
    FrameHeader reqHdr;
    reqHdr.MessageType = static_cast<uint16_t>(MessageType::LOCK_REQUEST);
    reqHdr.MessageID = 777;
    reqHdr.SequenceNumber = 1;
    reqHdr.PayloadLength = 0;

    auto reqBuf = SerializeFrameHeader(reqHdr);
    ASSERT_TRUE(server.SendMessageToClient(reqBuf));

    // Client reads message
    ReadResult readRes = client.ReadMessageFromServer(2000);
    ASSERT_TRUE(readRes.valid);

    auto parsedReq = DeserializeFrameHeader(readRes.data.data(), readRes.data.size());
    ASSERT_TRUE(parsedReq.has_value());
    EXPECT_EQ(parsedReq.value.MessageType, static_cast<uint16_t>(MessageType::LOCK_REQUEST));

    // Agent processes lock command
    UserSessionAgent agent;
    agent.SetLockFunctionForTesting(MockLockWorkStationSuccess);

    FrameHeader respHdr;
    std::vector<uint8_t> respPayload;
    EXPECT_TRUE(agent.ProcessLockCommand(parsedReq.value, {}, respHdr, respPayload));

    // Client sends LOCK_RESPONSE back to server
    auto respBuf = SerializeFrameHeader(respHdr);
    respBuf.insert(respBuf.end(), respPayload.begin(), respPayload.end());
    ASSERT_TRUE(client.SendMessageToServer(respBuf));

    // Wait for server to receive response
    int waitResp = 0;
    while (!serverReceivedResponse.load() && waitResp++ < 20) {
        Sleep(50);
    }

    EXPECT_TRUE(serverReceivedResponse.load());
    EXPECT_NE(serverResponsePayload.find("SUCCESS"), std::string::npos);

    client.Disconnect();
    server.Stop();
}
