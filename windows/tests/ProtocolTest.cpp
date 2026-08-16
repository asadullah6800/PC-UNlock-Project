#include <gtest/gtest.h>
#include "../../shared/protocol/ProtocolTypes.h"
#include "../../shared/protocol/SignedMessage.h"

using namespace MobileUnlock::Protocol;

// 1. FrameHeader Size Verification
TEST(ProtocolHeaderTest, ExactHeaderSize) {
    EXPECT_EQ(sizeof(FrameHeader), static_cast<size_t>(24));
    EXPECT_EQ(FRAME_HEADER_SIZE,   static_cast<size_t>(24));
}

TEST(ProtocolHeaderTest, SerializeDeserializeHeader) {
    FrameHeader original;
    original.Magic          = PROTOCOL_MAGIC;
    original.MajorVersion   = 1;
    original.MinorVersion   = 0;
    original.MessageType    = static_cast<uint16_t>(MessageType::AUTH_REQUEST);
    original.Reserved       = 0;
    original.MessageID      = 0x12345678;
    original.PayloadLength  = 256;
    original.SequenceNumber = 0x1122334455667788ULL;

    auto serialized = SerializeFrameHeader(original);
    EXPECT_EQ(serialized.size(), static_cast<size_t>(24));

    auto result = DeserializeFrameHeader(serialized.data(), serialized.size());
    ASSERT_TRUE(result.has_value());

    const auto& h = result.value;
    EXPECT_EQ(h.Magic,          PROTOCOL_MAGIC);
    EXPECT_EQ(h.MajorVersion,   1);
    EXPECT_EQ(h.MinorVersion,   0);
    EXPECT_EQ(h.MessageType,    static_cast<uint16_t>(MessageType::AUTH_REQUEST));
    EXPECT_EQ(h.MessageID,      static_cast<uint32_t>(0x12345678));
    EXPECT_EQ(h.PayloadLength,  static_cast<uint32_t>(256));
    EXPECT_EQ(h.SequenceNumber, static_cast<uint64_t>(0x1122334455667788ULL));
}

// 2. Canonical SignedMessage Size (EXACTLY 88 Bytes)
TEST(CanonicalMessageTest, ExactSignedMessageSize) {
    EXPECT_EQ(sizeof(SignedMessage),           static_cast<size_t>(88));
    EXPECT_EQ(CANONICAL_SIGNED_MESSAGE_SIZE,   static_cast<size_t>(88));
}

TEST(CanonicalMessageTest, SerializeDeserializeSignedMessage) {
    SignedMessage original;
    original.ProtocolVersion = 0x0100;
    std::memset(original.ServerIdentity, 0xAA, 16);
    std::memset(original.DeviceIdentity, 0xBB, 16);
    original.Operation  = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    original.RequestID  = 0x99887766;
    original.SessionID  = 0xDEADBEEFCAFEFACEULL;
    std::memset(original.Nonce, 0x77, 32);
    original.Timestamp  = 1718000000000ULL;

    auto serialized = SerializeSignedMessage(original);
    EXPECT_EQ(serialized.size(), static_cast<size_t>(88));

    auto result = DeserializeSignedMessage(serialized.data(), serialized.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value;
    EXPECT_EQ(msg.ProtocolVersion, static_cast<uint16_t>(0x0100));
    EXPECT_EQ(std::memcmp(msg.ServerIdentity, original.ServerIdentity, 16), 0);
    EXPECT_EQ(std::memcmp(msg.DeviceIdentity, original.DeviceIdentity, 16), 0);
    EXPECT_EQ(msg.Operation,  static_cast<uint16_t>(MessageType::AUTH_RESPONSE));
    EXPECT_EQ(msg.RequestID,  static_cast<uint32_t>(0x99887766));
    EXPECT_EQ(msg.SessionID,  static_cast<uint64_t>(0xDEADBEEFCAFEFACEULL));
    EXPECT_EQ(std::memcmp(msg.Nonce, original.Nonce, 32), 0);
    EXPECT_EQ(msg.Timestamp,  static_cast<uint64_t>(1718000000000ULL));
}

// 3. Invalid Message Rejection Tests
TEST(ProtocolValidationTest, InvalidMagicRejection) {
    std::vector<uint8_t> badMagicBuf(24, 0);
    badMagicBuf[0] = 0xFF;
    badMagicBuf[1] = 0xFF;

    auto result = DeserializeFrameHeader(badMagicBuf.data(), badMagicBuf.size());
    EXPECT_FALSE(result.has_value());
}

TEST(ProtocolValidationTest, InvalidVersionRejection) {
    FrameHeader badVersionHeader;
    badVersionHeader.Magic = PROTOCOL_MAGIC;
    badVersionHeader.MajorVersion = 99; // Invalid major version
    badVersionHeader.MessageType = static_cast<uint16_t>(MessageType::PING);
    auto serialized = SerializeFrameHeader(badVersionHeader);

    auto result = DeserializeFrameHeader(serialized.data(), serialized.size());
    EXPECT_FALSE(result.has_value());

    SignedMessage badVersionMsg;
    badVersionMsg.ProtocolVersion = 0x9999; // Invalid
    badVersionMsg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    auto serSigned = SerializeSignedMessage(badVersionMsg);
    auto r2 = DeserializeSignedMessage(serSigned.data(), serSigned.size());
    EXPECT_FALSE(r2.has_value());
}

TEST(ProtocolValidationTest, InvalidOpcodeRejection) {
    FrameHeader badOpcodeHeader;
    badOpcodeHeader.Magic = PROTOCOL_MAGIC;
    badOpcodeHeader.MajorVersion = PROTOCOL_MAJOR_VERSION;
    badOpcodeHeader.MessageType = 0x9999; // Non-existent opcode
    auto serialized = SerializeFrameHeader(badOpcodeHeader);

    auto result = DeserializeFrameHeader(serialized.data(), serialized.size());
    EXPECT_FALSE(result.has_value());

    SignedMessage badOpcodeMsg;
    badOpcodeMsg.ProtocolVersion = 0x0100;
    badOpcodeMsg.Operation = 0x9999; // Non-existent opcode
    auto serSigned = SerializeSignedMessage(badOpcodeMsg);
    auto r2 = DeserializeSignedMessage(serSigned.data(), serSigned.size());
    EXPECT_FALSE(r2.has_value());
}

TEST(ProtocolValidationTest, PayloadTooLargeRejection) {
    FrameHeader largePayloadHeader;
    largePayloadHeader.Magic = PROTOCOL_MAGIC;
    largePayloadHeader.MajorVersion = PROTOCOL_MAJOR_VERSION;
    largePayloadHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_REQUEST);
    largePayloadHeader.PayloadLength = 8192; // > MAX_PAYLOAD_SIZE (4096)
    auto serialized = SerializeFrameHeader(largePayloadHeader);

    auto result = DeserializeFrameHeader(serialized.data(), serialized.size());
    EXPECT_FALSE(result.has_value());
}

TEST(ProtocolValidationTest, TruncatedMessageRejection) {
    std::vector<uint8_t> shortBuf(10, 0);
    auto r1 = DeserializeFrameHeader(shortBuf.data(), shortBuf.size());
    EXPECT_FALSE(r1.has_value());

    std::vector<uint8_t> shortSignedMsg(50, 0);
    auto r2 = DeserializeSignedMessage(shortSignedMsg.data(), shortSignedMsg.size());
    EXPECT_FALSE(r2.has_value());
}
