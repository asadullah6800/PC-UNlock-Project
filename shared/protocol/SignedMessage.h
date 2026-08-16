#pragma once

#include "ProtocolTypes.h"
#include <vector>
#include <cstring>

namespace MobileUnlock::Protocol {

// Canonical SignedMessage struct representation (Exactly 88 Bytes)
#pragma pack(push, 1)
struct SignedMessage {
    uint16_t ProtocolVersion;
    uint8_t  ServerIdentity[16];
    uint8_t  DeviceIdentity[16];
    uint16_t Operation;
    uint32_t RequestID;
    uint64_t SessionID;
    uint8_t  Nonce[32];
    uint64_t Timestamp;

    SignedMessage()
        : ProtocolVersion(0x0100),
          Operation(0),
          RequestID(0),
          SessionID(0),
          Timestamp(0)
    {
        std::memset(ServerIdentity, 0, sizeof(ServerIdentity));
        std::memset(DeviceIdentity, 0, sizeof(DeviceIdentity));
        std::memset(Nonce,          0, sizeof(Nonce));
    }
};
#pragma pack(pop)

static_assert(sizeof(SignedMessage) == CANONICAL_SIGNED_MESSAGE_SIZE, "SignedMessage must be exactly 88 bytes");

// Serializes SignedMessage into Big-Endian network byte order
inline std::vector<uint8_t> SerializeSignedMessage(const SignedMessage& msg) {
    std::vector<uint8_t> buf(sizeof(SignedMessage));
    SignedMessage netMsg;

    netMsg.ProtocolVersion = HostToNetwork16(msg.ProtocolVersion);
    std::memcpy(netMsg.ServerIdentity, msg.ServerIdentity, 16);
    std::memcpy(netMsg.DeviceIdentity, msg.DeviceIdentity, 16);
    netMsg.Operation  = HostToNetwork16(msg.Operation);
    netMsg.RequestID  = HostToNetwork32(msg.RequestID);
    netMsg.SessionID  = HostToNetwork64(msg.SessionID);
    std::memcpy(netMsg.Nonce, msg.Nonce, 32);
    netMsg.Timestamp  = HostToNetwork64(msg.Timestamp);

    std::memcpy(buf.data(), &netMsg, sizeof(SignedMessage));
    return buf;
}

// Deserializes SignedMessage from Big-Endian network byte order
inline ParseResult<SignedMessage> DeserializeSignedMessage(const uint8_t* data, size_t len) {
    if (len != sizeof(SignedMessage) || data == nullptr) {
        return ParseResult<SignedMessage>();
    }

    SignedMessage netMsg;
    std::memcpy(&netMsg, data, sizeof(SignedMessage));

    SignedMessage msg;
    msg.ProtocolVersion = NetworkToHost16(netMsg.ProtocolVersion);
    std::memcpy(msg.ServerIdentity, netMsg.ServerIdentity, 16);
    std::memcpy(msg.DeviceIdentity, netMsg.DeviceIdentity, 16);
    msg.Operation  = NetworkToHost16(netMsg.Operation);
    msg.RequestID  = NetworkToHost32(netMsg.RequestID);
    msg.SessionID  = NetworkToHost64(netMsg.SessionID);
    std::memcpy(msg.Nonce, netMsg.Nonce, 32);
    msg.Timestamp  = NetworkToHost64(netMsg.Timestamp);

    if (msg.ProtocolVersion != 0x0100 || !IsValidMessageType(msg.Operation)) {
        return ParseResult<SignedMessage>();
    }

    return ParseResult<SignedMessage>(msg);
}

} // namespace MobileUnlock::Protocol
