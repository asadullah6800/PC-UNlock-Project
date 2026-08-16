import 'dart:typed_data';

class CanonicalSignedMessage {
  final int protocolVersion; // uint16
  final Uint8List serverIdentityBytes; // 16 bytes binary UUID
  final Uint8List deviceIdentityBytes; // 16 bytes binary UUID
  final int operation; // uint16
  final int requestId; // uint32
  final BigInt sessionId; // uint64
  final Uint8List nonceBytes; // 32 bytes
  final BigInt timestamp; // uint64 UNIX millis

  CanonicalSignedMessage({
    this.protocolVersion = 0x0100,
    required this.serverIdentityBytes,
    required this.deviceIdentityBytes,
    required this.operation,
    required this.requestId,
    required this.sessionId,
    required this.nonceBytes,
    required this.timestamp,
  }) {
    assert(serverIdentityBytes.length == 16, 'ServerIdentity must be 16 bytes');
    assert(deviceIdentityBytes.length == 16, 'DeviceIdentity must be 16 bytes');
    assert(nonceBytes.length == 32, 'Nonce must be 32 bytes');
  }

  // Serializes payload into Big-Endian network byte order (EXACTLY 88 Bytes)
  Uint8List toCanonicalBytes() {
    final bd = ByteData(88);
    int offset = 0;

    // 1. ProtocolVersion (uint16)
    bd.setUint16(offset, protocolVersion, Endian.big);
    offset += 2;

    // 2. ServerIdentity (16 bytes)
    for (int i = 0; i < 16; i++) {
      bd.setUint8(offset + i, serverIdentityBytes[i]);
    }
    offset += 16;

    // 3. DeviceIdentity (16 bytes)
    for (int i = 0; i < 16; i++) {
      bd.setUint8(offset + i, deviceIdentityBytes[i]);
    }
    offset += 16;

    // 4. Operation (uint16)
    bd.setUint16(offset, operation, Endian.big);
    offset += 2;

    // 5. RequestID (uint32)
    bd.setUint32(offset, requestId, Endian.big);
    offset += 4;

    // 6. SessionID (uint64)
    bd.setUint64(offset, sessionId.toInt(), Endian.big);
    offset += 8;

    // 7. Nonce (32 bytes)
    for (int i = 0; i < 32; i++) {
      bd.setUint8(offset + i, nonceBytes[i]);
    }
    offset += 32;

    // 8. Timestamp (uint64)
    bd.setUint64(offset, timestamp.toInt(), Endian.big);
    offset += 8;

    assert(offset == 88, 'CanonicalSignedMessage size must be exactly 88 bytes');
    return bd.buffer.asUint8List();
  }
}
