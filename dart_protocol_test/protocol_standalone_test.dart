/// Standalone Dart test — no Flutter SDK required.
/// Tests canonical 88-byte SignedMessage serialization.
/// Run with: dart run protocol_standalone_test.dart

import 'dart:typed_data';

// ── Inline copy of CanonicalSignedMessage ────────────────────────────────────

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

    // 1. ProtocolVersion (uint16) — 2 bytes
    bd.setUint16(offset, protocolVersion, Endian.big);
    offset += 2;

    // 2. ServerIdentity (16 bytes UUID raw binary)
    for (int i = 0; i < 16; i++) bd.setUint8(offset + i, serverIdentityBytes[i]);
    offset += 16;

    // 3. DeviceIdentity (16 bytes UUID raw binary)
    for (int i = 0; i < 16; i++) bd.setUint8(offset + i, deviceIdentityBytes[i]);
    offset += 16;

    // 4. Operation (uint16) — 2 bytes
    bd.setUint16(offset, operation, Endian.big);
    offset += 2;

    // 5. RequestID (uint32) — 4 bytes
    bd.setUint32(offset, requestId, Endian.big);
    offset += 4;

    // 6. SessionID (uint64) — 8 bytes
    bd.setUint64(offset, sessionId.toInt(), Endian.big);
    offset += 8;

    // 7. Nonce (32 bytes raw binary)
    for (int i = 0; i < 32; i++) bd.setUint8(offset + i, nonceBytes[i]);
    offset += 32;

    // 8. Timestamp (uint64) — 8 bytes
    bd.setUint64(offset, timestamp.toInt(), Endian.big);
    offset += 8;

    assert(offset == 88, 'CanonicalSignedMessage size must be exactly 88 bytes');
    return bd.buffer.asUint8List();
  }
}

// ── Minimal test harness ─────────────────────────────────────────────────────

int _passed = 0;
int _failed = 0;

void expect(dynamic actual, dynamic expected, {String? desc}) {
  if (actual == expected) {
    _passed++;
    print('  ✓  ${desc ?? ""}  ($actual == $expected)');
  } else {
    _failed++;
    print('  ✗  ${desc ?? ""}  EXPECTED $expected GOT $actual');
  }
}

void test(String name, void Function() body) {
  print('[TEST] $name');
  body();
}

// ── Tests ────────────────────────────────────────────────────────────────────

void main() {
  // ── Test 1: Exact 88-byte size ────────────────────────────────────────────
  test('CanonicalSignedMessage produces exactly 88 bytes', () {
    final serverUuid = Uint8List(16)..fillRange(0, 16, 0xAA);
    final deviceUuid = Uint8List(16)..fillRange(0, 16, 0xBB);
    final nonce = Uint8List(32)..fillRange(0, 32, 0x77);

    final msg = CanonicalSignedMessage(
      protocolVersion: 0x0100,
      serverIdentityBytes: serverUuid,
      deviceIdentityBytes: deviceUuid,
      operation: 0x0022,
      requestId: 12345,
      sessionId: BigInt.from(987654321),
      nonceBytes: nonce,
      timestamp: BigInt.from(1718000000000),
    );

    final bytes = msg.toCanonicalBytes();
    expect(bytes.length, 88, desc: 'size == 88');
  });

  // ── Test 2: Field layout / Big-Endian correctness ─────────────────────────
  test('CanonicalSignedMessage serializes fields in correct Big-Endian order', () {
    final serverUuid = Uint8List(16)..fillRange(0, 16, 0x11);
    final deviceUuid = Uint8List(16)..fillRange(0, 16, 0x22);
    final nonce = Uint8List(32)..fillRange(0, 32, 0x33);
    const int requestId = 0xDEADBEEF;
    final BigInt sessionId = BigInt.from(0xCAFEBABE00000000);
    final BigInt timestamp = BigInt.from(1718000000000);

    final msg = CanonicalSignedMessage(
      protocolVersion: 0x0100,
      serverIdentityBytes: serverUuid,
      deviceIdentityBytes: deviceUuid,
      operation: 0x0022,
      requestId: requestId,
      sessionId: sessionId,
      nonceBytes: nonce,
      timestamp: timestamp,
    );

    final b = msg.toCanonicalBytes();

    // ProtocolVersion at offset 0-1 Big-Endian
    final pv = (b[0] << 8) | b[1];
    expect(pv, 0x0100, desc: 'ProtocolVersion BE at offset 0');

    // ServerIdentity at offset 2-17
    expect(b[2], 0x11, desc: 'ServerIdentity[0] at offset 2');
    expect(b[17], 0x11, desc: 'ServerIdentity[15] at offset 17');

    // DeviceIdentity at offset 18-33
    expect(b[18], 0x22, desc: 'DeviceIdentity[0] at offset 18');
    expect(b[33], 0x22, desc: 'DeviceIdentity[15] at offset 33');

    // Operation at offset 34-35
    final op = (b[34] << 8) | b[35];
    expect(op, 0x0022, desc: 'Operation BE at offset 34');

    // RequestID at offset 36-39
    final rid = (b[36] << 24) | (b[37] << 16) | (b[38] << 8) | b[39];
    expect(rid, requestId, desc: 'RequestID BE at offset 36');

    // Nonce at offset 48-79
    expect(b[48], 0x33, desc: 'Nonce[0] at offset 48');
    expect(b[79], 0x33, desc: 'Nonce[31] at offset 79');

    // Total size
    expect(b.length, 88, desc: 'total size');
  });

  // ── Test 3: Field boundary — Nonce is exactly 32 bytes, not polluted ──────
  test('Nonce field occupies exactly bytes 48-79 (32 bytes)', () {
    final nonce = Uint8List(32)..fillRange(0, 32, 0xFF);
    final msg = CanonicalSignedMessage(
      protocolVersion: 0x0100,
      serverIdentityBytes: Uint8List(16),
      deviceIdentityBytes: Uint8List(16),
      operation: 0x0001,
      requestId: 0,
      sessionId: BigInt.zero,
      nonceBytes: nonce,
      timestamp: BigInt.zero,
    );
    final b = msg.toCanonicalBytes();
    // Verify all 32 nonce bytes at their expected positions
    bool allFF = true;
    for (int i = 48; i < 80; i++) {
      if (b[i] != 0xFF) { allFF = false; break; }
    }
    expect(allFF, true, desc: 'Nonce bytes 48-79 are all 0xFF');
    // Verify Timestamp field (bytes 80-87) is zero when zero is given
    bool timestampZero = true;
    for (int i = 80; i < 88; i++) {
      if (b[i] != 0x00) { timestampZero = false; break; }
    }
    expect(timestampZero, true, desc: 'Timestamp bytes 80-87 are zero');
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  print('');
  print('══════════════════════════════════════════════');
  print('Dart Protocol Tests: $_passed passed, $_failed failed');
  if (_failed > 0) {
    print('RESULT: FAIL');
    throw Exception('$_failed test(s) failed');
  } else {
    print('RESULT: PASS — 88-byte canonical protocol verified');
  }
  print('══════════════════════════════════════════════');
}
