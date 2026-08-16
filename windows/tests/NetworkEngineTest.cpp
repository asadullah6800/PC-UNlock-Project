#include <gtest/gtest.h>
#include "../network/NetworkEngine.h"
#include "../network/TlsContext.h"
#include "../../shared/protocol/ProtocolTypes.h"
#include <atomic>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

using namespace MobileUnlock::Network;
using namespace MobileUnlock::Protocol;

TEST(TlsContextTest, ServerCredentialsInitialization) {
    TlsContext tls;
    EXPECT_TRUE(tls.InitializeServerCredentials());
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST(TlsContextTest, StrictTls13Enforcement) {
    TlsContext tls;
    const auto& config = tls.GetConfig();
    EXPECT_TRUE(config.EnableTls13);
    EXPECT_FALSE(config.EnableTls12); // TLS 1.2 must be disabled
}

TEST(NetworkEngineTest, ServerLifecycle) {
    NetworkEngine engine(8445);
    EXPECT_EQ(engine.GetPort(), static_cast<uint16_t>(8445));
    EXPECT_FALSE(engine.IsRunning());

    bool started = engine.Start([](uint64_t, const FrameHeader&, const std::vector<uint8_t>&) {});
    EXPECT_TRUE(started);
    EXPECT_TRUE(engine.IsRunning());

    engine.Stop();
    EXPECT_FALSE(engine.IsRunning());
}

TEST(NetworkEngineTest, RateLimiting) {
    NetworkEngine engine(8446);
    std::string testIp = "192.168.1.100";

    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(engine.CheckRateLimit(testIp));
    }

    // 6th attempt within 1 minute should be rate-limited
    EXPECT_FALSE(engine.CheckRateLimit(testIp));
}

TEST(NetworkEngineTest, ClientConnectAndReceiveFrame) {
    uint16_t testPort = 8447;
    NetworkEngine engine(testPort);

    std::atomic<bool> frameReceived(false);
    FrameHeader receivedHeader{};
    std::vector<uint8_t> receivedPayload;

    bool started = engine.Start([&](uint64_t, const FrameHeader& h, const std::vector<uint8_t>& p) {
        receivedHeader = h;
        receivedPayload = p;
        frameReceived.store(true);
    });
    ASSERT_TRUE(started);

    Sleep(100);

    // Connect raw TCP socket to test framing
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(sock, INVALID_SOCKET);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(testPort);

    int connResult = connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    ASSERT_EQ(connResult, 0);

    Sleep(100);

    // Send a valid PING frame
    FrameHeader pingHeader;
    pingHeader.Magic = PROTOCOL_MAGIC;
    pingHeader.MajorVersion = PROTOCOL_MAJOR_VERSION;
    pingHeader.MinorVersion = PROTOCOL_MINOR_VERSION;
    pingHeader.MessageType = static_cast<uint16_t>(MessageType::PING);
    pingHeader.MessageID = 777;
    pingHeader.PayloadLength = 4;
    pingHeader.SequenceNumber = 10;

    auto headerBytes = SerializeFrameHeader(pingHeader);
    std::vector<uint8_t> payload = { 0xDE, 0xAD, 0xBE, 0xEF };
    headerBytes.insert(headerBytes.end(), payload.begin(), payload.end());

    int sent = send(sock, reinterpret_cast<const char*>(headerBytes.data()), static_cast<int>(headerBytes.size()), 0);
    EXPECT_EQ(sent, static_cast<int>(headerBytes.size()));

    Sleep(300);

    EXPECT_TRUE(frameReceived.load());
    EXPECT_EQ(receivedHeader.Magic, PROTOCOL_MAGIC);
    EXPECT_EQ(receivedHeader.MessageType, static_cast<uint16_t>(MessageType::PING));
    EXPECT_EQ(receivedHeader.MessageID, static_cast<uint32_t>(777));
    EXPECT_EQ(receivedPayload.size(), static_cast<size_t>(4));
    EXPECT_EQ(receivedPayload[0], 0xDE);

    closesocket(sock);
    engine.Stop();
}
