import 'dart:typed_data';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_fingerprint_unlock/security/biometric_security_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late BiometricSecurityService service;
  late List<MethodCall> log;

  setUp(() {
    log = <MethodCall>[];
    service = BiometricSecurityService();

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel(BiometricSecurityService.channelName),
      (MethodCall methodCall) async {
        log.add(methodCall);
        switch (methodCall.method) {
          case 'isBiometricAvailable':
            return {'available': true, 'status': 'SUCCESS'};
          case 'isStrongBoxSupported':
            return false;
          case 'getKeyStatus':
            return {'exists': true, 'securityLevel': 'TEE', 'isInvalidated': false};
          case 'ensureKeyReady':
            return {'exists': true, 'securityLevel': 'TEE', 'isInvalidated': false};
          case 'getPublicKey':
            return Uint8List(91); // Fake X.509
          case 'signCanonicalMessage':
            final payload = methodCall.arguments['payload'] as Uint8List;
            if (payload.length != 88) {
              throw PlatformException(code: 'INVALID_PAYLOAD', message: 'Must be 88 bytes');
            }
            // Return 64-byte non-zero signature
            final sig = Uint8List(64);
            for (int i = 0; i < 64; i++) {
              sig[i] = (i + 1) & 0xFF;
            }
            return sig;
          default:
            return null;
        }
      },
    );
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel(BiometricSecurityService.channelName),
      null,
    );
  });

  test('checkBiometricCapability parses capability successfully', () async {
    final cap = await service.checkBiometricCapability();
    expect(cap.available, isTrue);
    expect(cap.status, equals('SUCCESS'));
  });

  test('getKeyStatus returns parsed KeyStatus', () async {
    final status = await service.getKeyStatus();
    expect(status.exists, isTrue);
    expect(status.securityLevel, equals('TEE'));
    expect(status.isInvalidated, isFalse);
  });

  test('signCanonicalMessage succeeds with 88-byte payload and returns 64-byte signature', () async {
    final payload88 = Uint8List(88);
    for (int i = 0; i < 88; i++) {
      payload88[i] = i & 0xFF;
    }

    final sig = await service.signCanonicalMessage(payload88);
    expect(sig.length, equals(64));
    expect(sig.every((b) => b == 0), isFalse); // Non-zero
  });

  test('signCanonicalMessage rejects payload with length != 88 without invoking channel', () async {
    final badPayload87 = Uint8List(87);
    expect(
      () => service.signCanonicalMessage(badPayload87),
      throwsA(isA<InvalidPayloadException>()),
    );
    expect(log.where((c) => c.method == 'signCanonicalMessage'), isEmpty);

    final badPayload89 = Uint8List(89);
    expect(
      () => service.signCanonicalMessage(badPayload89),
      throwsA(isA<InvalidPayloadException>()),
    );
  });

  test('signCanonicalMessage maps BIOMETRIC_CANCELLED platform exception', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel(BiometricSecurityService.channelName),
      (MethodCall call) async {
        throw PlatformException(code: 'BIOMETRIC_CANCELLED', message: 'User pressed cancel');
      },
    );

    final payload88 = Uint8List(88);
    expect(
      () => service.signCanonicalMessage(payload88),
      throwsA(isA<BiometricCancelledException>()),
    );
  });

  test('signCanonicalMessage maps KEY_INVALIDATED platform exception', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel(BiometricSecurityService.channelName),
      (MethodCall call) async {
        throw PlatformException(code: 'KEY_INVALIDATED', message: 'Biometric enrollment changed');
      },
    );

    final payload88 = Uint8List(88);
    expect(
      () => service.signCanonicalMessage(payload88),
      throwsA(isA<KeyInvalidatedException>()),
    );
  });
}
