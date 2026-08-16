#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <vector>
#include <string>

namespace MobileUnlock::Protocol {

// Protocol constants
constexpr uint16_t PROTOCOL_MAGIC = 0x4D55; // 'M', 'U'
constexpr uint8_t PROTOCOL_MAJOR_VERSION = 1;
constexpr uint8_t PROTOCOL_MINOR_VERSION = 0;
constexpr uint32_t MAX_PAYLOAD_SIZE = 4096;
constexpr size_t FRAME_HEADER_SIZE = 24;
constexpr size_t CANONICAL_SIGNED_MESSAGE_SIZE = 88;

// Opcode Enumeration
enum class MessageType : uint16_t {
    UNKNOWN             = 0x0000,
    DISCOVER            = 0x0001,
    DISCOVERY_RESPONSE  = 0x0002,
    PAIR_REQUEST        = 0x0010,
    PAIR_RESPONSE       = 0x0011,
    PAIR_CONFIRM        = 0x0012,
    PAIR_COMPLETE       = 0x0013,
    AUTH_REQUEST        = 0x0020,
    AUTH_CHALLENGE      = 0x0021,
    AUTH_RESPONSE       = 0x0022,
    AUTH_SUCCESS        = 0x0023,
    AUTH_FAILURE        = 0x0024,
    LOCK_REQUEST        = 0x0030,
    LOCK_RESPONSE       = 0x0031,
    STATUS_REQUEST      = 0x0040,
    STATUS_RESPONSE     = 0x0041,
    UNPAIR_REQUEST      = 0x0050,
    UNPAIR_RESPONSE     = 0x0051,
    PING                = 0x00E0,
    PONG                = 0x00E1,
    PROTO_ERROR         = 0x00FF
};

// PC System States
enum class PcState : uint32_t {
    UNKNOWN        = 0,
    OFFLINE        = 1,
    ONLINE         = 2,
    LOCKED         = 3,
    UNLOCKED       = 4,
    SUSPENDED      = 5,
    SLEEPING       = 6,
    PAIRING        = 7,
    AUTHENTICATING = 8,
    PROTO_ERROR    = 9
};

// Error Codes
enum class ErrorCode : uint32_t {
    SUCCESS                 = 0,
    INVALID_MAGIC           = 1,
    INVALID_VERSION         = 2,
    INVALID_OPCODE          = 3,
    PAYLOAD_TOO_LARGE       = 4,
    MALFORMED_HEADER        = 5,
    UNAUTHORIZED            = 6,
    DEVICE_REVOKED          = 7,
    NONCE_EXPIRED           = 8,
    REPLAY_DETECTED         = 9,
    RATE_LIMITED            = 10,
    SERVICE_UNAVAILABLE     = 11,
    IPC_COMMUNICATION_ERROR = 12,
    INTERNAL_ERROR          = 99
};

// Wire Frame Header Structure (24 Bytes, packed)
#pragma pack(push, 1)
struct FrameHeader {
    uint16_t Magic;
    uint8_t  MajorVersion;
    uint8_t  MinorVersion;
    uint16_t MessageType;
    uint16_t Reserved;
    uint32_t MessageID;
    uint32_t PayloadLength;
    uint64_t SequenceNumber;

    FrameHeader()
        : Magic(PROTOCOL_MAGIC),
          MajorVersion(PROTOCOL_MAJOR_VERSION),
          MinorVersion(PROTOCOL_MINOR_VERSION),
          MessageType(0),
          Reserved(0),
          MessageID(0),
          PayloadLength(0),
          SequenceNumber(0) {}
};
#pragma pack(pop)

static_assert(sizeof(FrameHeader) == FRAME_HEADER_SIZE, "FrameHeader must be exactly 24 bytes");

// Simple result wrapper replacing std::optional for GCC 6.3 compatibility
template<typename T>
struct ParseResult {
    bool valid;
    T value;
    ParseResult() : valid(false), value() {}
    ParseResult(const T& v) : valid(true), value(v) {}
    bool has_value() const { return valid; }
};

// Helper byte-swapping functions for network byte order (Big-Endian)
inline uint16_t HostToNetwork16(uint16_t val) {
#if defined(_MSC_VER)
    return _byteswap_ushort(val);
#else
    return __builtin_bswap16(val);
#endif
}

inline uint32_t HostToNetwork32(uint32_t val) {
#if defined(_MSC_VER)
    return _byteswap_ulong(val);
#else
    return __builtin_bswap32(val);
#endif
}

inline uint64_t HostToNetwork64(uint64_t val) {
#if defined(_MSC_VER)
    return _byteswap_uint64(val);
#else
    return __builtin_bswap64(val);
#endif
}

inline uint16_t NetworkToHost16(uint16_t val) { return HostToNetwork16(val); }
inline uint32_t NetworkToHost32(uint32_t val) { return HostToNetwork32(val); }
inline uint64_t NetworkToHost64(uint64_t val) { return HostToNetwork64(val); }

// Serializes FrameHeader into Big-Endian network byte order
inline std::vector<uint8_t> SerializeFrameHeader(const FrameHeader& header) {
    std::vector<uint8_t> buf(sizeof(FrameHeader));
    FrameHeader netHeader;
    netHeader.Magic          = HostToNetwork16(header.Magic);
    netHeader.MajorVersion   = header.MajorVersion;
    netHeader.MinorVersion   = header.MinorVersion;
    netHeader.MessageType    = HostToNetwork16(header.MessageType);
    netHeader.Reserved       = HostToNetwork16(header.Reserved);
    netHeader.MessageID      = HostToNetwork32(header.MessageID);
    netHeader.PayloadLength  = HostToNetwork32(header.PayloadLength);
    netHeader.SequenceNumber = HostToNetwork64(header.SequenceNumber);
    std::memcpy(buf.data(), &netHeader, sizeof(FrameHeader));
    return buf;
}

// Helper validating known MessageType opcodes
inline bool IsValidMessageType(uint16_t opcode) {
    switch (static_cast<MessageType>(opcode)) {
    case MessageType::DISCOVER:
    case MessageType::DISCOVERY_RESPONSE:
    case MessageType::PAIR_REQUEST:
    case MessageType::PAIR_RESPONSE:
    case MessageType::PAIR_CONFIRM:
    case MessageType::PAIR_COMPLETE:
    case MessageType::AUTH_REQUEST:
    case MessageType::AUTH_CHALLENGE:
    case MessageType::AUTH_RESPONSE:
    case MessageType::AUTH_SUCCESS:
    case MessageType::AUTH_FAILURE:
    case MessageType::LOCK_REQUEST:
    case MessageType::LOCK_RESPONSE:
    case MessageType::STATUS_REQUEST:
    case MessageType::STATUS_RESPONSE:
    case MessageType::UNPAIR_REQUEST:
    case MessageType::UNPAIR_RESPONSE:
    case MessageType::PING:
    case MessageType::PONG:
    case MessageType::PROTO_ERROR:
        return true;
    default:
        return false;
    }
}

// Deserializes FrameHeader from Big-Endian network byte order
inline ParseResult<FrameHeader> DeserializeFrameHeader(const uint8_t* data, size_t len) {
    if (len < sizeof(FrameHeader) || data == nullptr) {
        return ParseResult<FrameHeader>();
    }
    FrameHeader netHeader;
    std::memcpy(&netHeader, data, sizeof(FrameHeader));

    FrameHeader h;
    h.Magic          = NetworkToHost16(netHeader.Magic);
    h.MajorVersion   = netHeader.MajorVersion;
    h.MinorVersion   = netHeader.MinorVersion;
    h.MessageType    = NetworkToHost16(netHeader.MessageType);
    h.Reserved       = NetworkToHost16(netHeader.Reserved);
    h.MessageID      = NetworkToHost32(netHeader.MessageID);
    h.PayloadLength  = NetworkToHost32(netHeader.PayloadLength);
    h.SequenceNumber = NetworkToHost64(netHeader.SequenceNumber);

    if (h.Magic != PROTOCOL_MAGIC || h.MajorVersion != PROTOCOL_MAJOR_VERSION || h.PayloadLength > MAX_PAYLOAD_SIZE || !IsValidMessageType(h.MessageType)) {
        return ParseResult<FrameHeader>();
    }
    return ParseResult<FrameHeader>(h);
}

} // namespace MobileUnlock::Protocol
