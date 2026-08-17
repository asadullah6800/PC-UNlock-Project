import 'dart:typed_data';
import 'dart:convert';

// Opcode constants
const int OPCODE_AUTH_REQUEST   = 0x0020;
const int OPCODE_AUTH_CHALLENGE = 0x0021;
const int OPCODE_AUTH_RESPONSE  = 0x0022;
const int OPCODE_AUTH_SUCCESS   = 0x0023;
const int OPCODE_AUTH_FAILURE   = 0x0024;

const int PROTOCOL_MAGIC = 0x4D55;
const int CANONICAL_SIGNED_MESSAGE_SIZE = 88;
const int SIGNATURE_SIZE = 64;

class AuthChallenge {
  final int sessionId;
  final Uint8List nonce;
  final Uint8List serverIdentity;
  final int timestamp;

  AuthChallenge({
    required this.sessionId,
    required this.nonce,
    required this.serverIdentity,
    required this.timestamp,
  });

  factory AuthChallenge.fromJson(Map<String, dynamic> json) {
    return AuthChallenge(
      sessionId: json['sessionId'] as int,
      nonce: _hexToBytes(json['nonce'] as String),
      serverIdentity: _hexToBytes(json['serverIdentity'] as String),
      timestamp: json['timestamp'] as int,
    );
  }

  static Uint8List _hexToBytes(String hex) {
    final bytes = <int>[];
    for (int i = 0; i < hex.length; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(bytes);
  }
}

/// Builds exact 88-byte Big-Endian canonical SignedMessage buffer
Uint8List buildCanonicalSignedMessage({
  required int protocolVersion,
  required Uint8List serverIdentity,
  required Uint8List deviceIdentity,
  required int operation,
  required int requestId,
  required int sessionId,
  required Uint8List nonce,
  required int timestamp,
}) {
  final byteData = ByteData(CANONICAL_SIGNED_MESSAGE_SIZE);
  int offset = 0;

  // 1. ProtocolVersion (2 bytes, Big-Endian)
  byteData.setUint16(offset, protocolVersion, Endian.big);
  offset += 2;

  // 2. ServerIdentity (16 bytes)
  final buffer = byteData.buffer.asUint8List();
  buffer.setRange(offset, offset + 16, serverIdentity);
  offset += 16;

  // 3. DeviceIdentity (16 bytes)
  buffer.setRange(offset, offset + 16, deviceIdentity);
  offset += 16;

  // 4. Operation (2 bytes, Big-Endian)
  byteData.setUint16(offset, operation, Endian.big);
  offset += 2;

  // 5. RequestID (4 bytes, Big-Endian)
  byteData.setUint32(offset, requestId, Endian.big);
  offset += 4;

  // 6. SessionID (8 bytes, Big-Endian)
  byteData.setUint64(offset, sessionId, Endian.big);
  offset += 8;

  // 7. Nonce (32 bytes)
  buffer.setRange(offset, offset + 32, nonce);
  offset += 32;

  // 8. Timestamp (8 bytes, Big-Endian)
  byteData.setUint64(offset, timestamp, Endian.big);
  offset += 8;

  assert(offset == CANONICAL_SIGNED_MESSAGE_SIZE);
  return buffer;
}

void main() {
  print('=== Running Phase 5 Authentication Protocol Tests ===');

  // Test 1: AuthChallenge JSON Deserialization
  final challengeJson = {
    'sessionId': 5005,
    'nonce': '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    'serverIdentity': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'timestamp': 1700000000000,
  };
  final challenge = AuthChallenge.fromJson(challengeJson);
  assert(challenge.sessionId == 5005);
  assert(challenge.nonce.length == 32);
  assert(challenge.nonce[0] == 0x01 && challenge.nonce[31] == 0x20);
  assert(challenge.serverIdentity.length == 16);
  assert(challenge.timestamp == 1700000000000);
  print('Test 1: AuthChallenge Deserialization PASSED');

  // Test 2: Canonical SignedMessage exact 88-byte alignment
  final serverId = Uint8List(16)..fillRange(0, 16, 0xAA);
  final deviceId = Uint8List(16)..fillRange(0, 16, 0xBB);
  final nonce = Uint8List(32);
  for (int i = 0; i < 32; i++) nonce[i] = i + 1;

  final canonicalMsg = buildCanonicalSignedMessage(
    protocolVersion: 0x0100,
    serverIdentity: serverId,
    deviceIdentity: deviceId,
    operation: OPCODE_AUTH_RESPONSE,
    requestId: 1001,
    sessionId: 5005,
    nonce: nonce,
    timestamp: 1700000000000,
  );

  assert(canonicalMsg.length == 88, 'Canonical message must be exactly 88 bytes');
  final bd = ByteData.sublistView(canonicalMsg);
  assert(bd.getUint16(0, Endian.big) == 0x0100);
  assert(bd.getUint16(34, Endian.big) == 0x0022); // Operation at offset 34
  assert(bd.getUint32(36, Endian.big) == 1001);   // RequestID at offset 36
  assert(bd.getUint64(40, Endian.big) == 5005);   // SessionID at offset 40
  assert(bd.getUint64(80, Endian.big) == 1700000000000); // Timestamp at offset 80
  print('Test 2: Canonical SignedMessage 88B Layout PASSED');

  // Test 3: AUTH_RESPONSE payload combination (88B message + 64B signature = 152B)
  final mockSignature = Uint8List(64)..fillRange(0, 64, 0x55);
  final authResponsePayload = Uint8List(88 + 64);
  authResponsePayload.setRange(0, 88, canonicalMsg);
  authResponsePayload.setRange(88, 152, mockSignature);
  assert(authResponsePayload.length == 152, 'AUTH_RESPONSE payload must be 152 bytes');
  print('Test 3: AUTH_RESPONSE 152B Payload Assembly PASSED');

  print('=== ALL DART PROTOCOL ASSERTIONS PASSED ===');
}
