#include <gtest/gtest.h>
#include "../ipc/SecureIPC.h"
#include "../../shared/protocol/ProtocolTypes.h"
#include <atomic>
#include <sstream>
#include <windows.h>

using namespace MobileUnlock::IPC;
using namespace MobileUnlock::Protocol;

TEST(IPCTest, ServerClientConnectionLifecycle) {
    std::wostringstream oss;
    oss << L"\\\\.\\pipe\\MobileUnlockTestPipe_" << GetCurrentProcessId();
    std::wstring testPipeName = oss.str();

    NamedPipeServer server(testPipeName);
    std::atomic<bool> messageReceived(false);
    FrameHeader receivedHeader;
    std::memset(&receivedHeader, 0, sizeof(receivedHeader));

    bool serverStarted = server.Start([&](const std::vector<uint8_t>& data) {
        auto r = DeserializeFrameHeader(data.data(), data.size());
        if (r.has_value()) {
            receivedHeader = r.value;
            messageReceived.store(true);
        }
    });

    ASSERT_TRUE(serverStarted);

    Sleep(200);

    NamedPipeClient client(testPipeName);
    bool connected = client.Connect(2000);
    ASSERT_TRUE(connected);

    FrameHeader pingHeader;
    pingHeader.MessageType    = static_cast<uint16_t>(MessageType::PING);
    pingHeader.MessageID      = 42;
    pingHeader.SequenceNumber = 100;

    auto buf = SerializeFrameHeader(pingHeader);
    bool sent = client.SendMessageToServer(buf);
    EXPECT_TRUE(sent);

    Sleep(300);

    EXPECT_TRUE(messageReceived.load());
    EXPECT_EQ(receivedHeader.MessageType, static_cast<uint16_t>(MessageType::PING));
    EXPECT_EQ(receivedHeader.MessageID,   static_cast<uint32_t>(42));

    client.Disconnect();
    server.Stop();
}
