import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_fingerprint_unlock/models/authentication_models.dart';
import 'package:mobile_fingerprint_unlock/services/authentication_service.dart';

void main() {
  group('AuthenticationService Tests', () {
    late AuthenticationService authService;

    setUp(() {
      authService = AuthenticationService();
    });

    test('buildCanonicalSignedMessage generates exactly 88 bytes in Big-Endian', () {
      final serverId = Uint8List(16)..fillRange(0, 16, 0xAA);
      final deviceId = Uint8List(16)..fillRange(0, 16, 0xBB);
      final nonce = Uint8List(32)..fillRange(0, 32, 0x11);

      final canonicalBytes = authService.buildCanonicalSignedMessage(
        serverIdentity: serverId,
        deviceIdentity: deviceId,
        requestId: 1001,
        sessionId: 5005,
        nonce: nonce,
        timestamp: 1700000000000,
      );

      expect(canonicalBytes.length, equals(88));

      final bd = ByteData.sublistView(canonicalBytes);
      expect(bd.getUint16(0, Endian.big), equals(0x0100)); // Version
      expect(bd.getUint16(34, Endian.big), equals(0x0022)); // Operation: AUTH_RESPONSE
      expect(bd.getUint32(36, Endian.big), equals(1001)); // RequestID
      expect(bd.getUint64(40, Endian.big), equals(5005)); // SessionID
      expect(bd.getUint64(80, Endian.big), equals(1700000000000)); // Timestamp
    });

    test('AuthChallenge deserialization parses hex nonce and server identity', () {
      final json = {
        'sessionId': 42,
        'nonce': '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        'serverIdentity': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'timestamp': 1700000000000,
      };

      final challenge = AuthChallenge.fromJson(json);
      expect(challenge.sessionId, equals(42));
      expect(challenge.nonce.length, equals(32));
      expect(challenge.nonce[0], equals(0x01));
      expect(challenge.nonce[31], equals(0x20));
      expect(challenge.serverIdentity.length, equals(16));
      expect(challenge.serverIdentity[0], equals(0xAA));
      expect(challenge.timestamp, equals(1700000000000));
    });
  });
}
