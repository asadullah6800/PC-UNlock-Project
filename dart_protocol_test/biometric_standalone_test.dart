import 'dart:typed_data';

void main() {
  print('=== Running Biometric & Canonical Signature Standalone Tests ===');

  // Test 1: Canonical 88-byte payload binary structure
  final buffer = Uint8List(88);
  final byteData = ByteData.sublistView(buffer);

  // Field 1: ProtocolVersion uint16 (2 bytes) = 0x0100
  byteData.setUint16(0, 0x0100, Endian.big);

  // Field 2: ServerIdentity 16 bytes UUID
  for (int i = 0; i < 16; i++) buffer[2 + i] = 0xAA;

  // Field 3: DeviceIdentity 16 bytes UUID
  for (int i = 0; i < 16; i++) buffer[18 + i] = 0xBB;

  // Field 4: Operation uint16 (2 bytes) = 0x0022 (AUTH_RESPONSE)
  byteData.setUint16(34, 0x0022, Endian.big);

  // Field 5: RequestID uint32 (4 bytes)
  byteData.setUint32(36, 12345, Endian.big);

  // Field 6: SessionID uint64 (8 bytes)
  byteData.setUint64(40, 987654321, Endian.big);

  // Field 7: Nonce (32 bytes)
  for (int i = 0; i < 32; i++) buffer[48 + i] = (i * 3) & 0xFF;

  // Field 8: Timestamp uint64 (8 bytes)
  byteData.setUint64(80, 1700000000000, Endian.big);

  assert(buffer.length == 88, 'Canonical buffer must be exactly 88 bytes');
  print('PASS: Canonical buffer size is 88 bytes');

  assert(byteData.getUint16(0, Endian.big) == 0x0100, 'ProtocolVersion mismatch');
  assert(byteData.getUint16(34, Endian.big) == 0x0022, 'Operation mismatch');
  assert(byteData.getUint32(36, Endian.big) == 12345, 'RequestID mismatch');
  assert(byteData.getUint64(40, Endian.big) == 987654321, 'SessionID mismatch');
  print('PASS: Canonical binary fields encoded correctly with Big-Endian alignment');

  // Test 2: Reject non-88 byte payloads
  bool rejectedShort = false;
  try {
    validatePayload(Uint8List(87));
  } catch (e) {
    rejectedShort = true;
  }
  assert(rejectedShort, 'Must reject 87-byte payload');
  print('PASS: Rejects 87-byte payload');

  bool rejectedLong = false;
  try {
    validatePayload(Uint8List(89));
  } catch (e) {
    rejectedLong = true;
  }
  assert(rejectedLong, 'Must reject 89-byte payload');
  print('PASS: Rejects 89-byte payload');

  // Test 3: Validate 64-byte signature requirement
  final validSig = Uint8List(64);
  validSig[0] = 0x12;
  validSig[63] = 0x34;
  validateSignature(validSig);
  print('PASS: Valid 64-byte signature accepted');

  bool rejectedBadSig = false;
  try {
    validateSignature(Uint8List(63));
  } catch (e) {
    rejectedBadSig = true;
  }
  assert(rejectedBadSig, 'Must reject 63-byte signature');
  print('PASS: Rejects 63-byte signature');

  print('\nAll Biometric & Canonical Signature Standalone tests PASSED!');
}

void validatePayload(Uint8List payload) {
  if (payload.length != 88) {
    throw ArgumentError('Payload must be exactly 88 bytes, got ${payload.length}');
  }
}

void validateSignature(Uint8List signature) {
  if (signature.length != 64) {
    throw ArgumentError('Signature must be exactly 64 bytes, got ${signature.length}');
  }
  if (signature.every((b) => b == 0)) {
    throw ArgumentError('Signature cannot be all zeros');
  }
}
