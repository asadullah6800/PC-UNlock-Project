import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_fingerprint_unlock/models/canonical_signed_message.dart';

void main() {
  group('CanonicalSignedMessage Protocol Tests', () {
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

      final canonicalBytes = msg.toCanonicalBytes();

      expect(canonicalBytes.length, equals(88));
    });
  });
}
