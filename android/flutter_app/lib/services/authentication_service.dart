import 'dart:typed_data';
import '../models/authentication_models.dart';
import '../models/canonical_signed_message.dart';
import '../security/biometric_security_service.dart';
import 'service_locator.dart';

class AuthenticationService {
  /// Builds exact 88-byte Big-Endian canonical SignedMessage
  Uint8List buildCanonicalSignedMessage({
    required Uint8List serverIdentity,
    required Uint8List deviceIdentity,
    required int requestId,
    required int sessionId,
    required Uint8List nonce,
    required int timestamp,
  }) {
    final msg = CanonicalSignedMessage(
      serverIdentityBytes: serverIdentity,
      deviceIdentityBytes: deviceIdentity,
      operation: 0x0022, // AUTH_RESPONSE
      requestId: requestId,
      sessionId: BigInt.from(sessionId),
      nonceBytes: nonce,
      timestamp: BigInt.from(timestamp),
    );
    return msg.toCanonicalBytes();
  }

  /// Performs biometric signing over challenge and returns 152-byte payload (88B canonical + 64B signature)
  Future<Uint8List> signAuthChallenge({
    required AuthChallenge challenge,
    required Uint8List deviceIdentity,
    required int requestId,
  }) async {
    // 1. Build canonical 88-byte message
    final canonicalBytes = buildCanonicalSignedMessage(
      serverIdentity: challenge.serverIdentity,
      deviceIdentity: deviceIdentity,
      requestId: requestId,
      sessionId: challenge.sessionId,
      nonce: challenge.nonce,
      timestamp: challenge.timestamp,
    );

    // 2. Obtain 64-byte biometric signature from Android Keystore
    final signature = await locator.biometricSecurityService.signCanonicalMessage(canonicalBytes);
    if (signature.length != 64) {
      throw BiometricSecurityException('INVALID_SIGNATURE_LENGTH', 'Signature must be exactly 64 bytes');
    }

    // 3. Assemble 152-byte AUTH_RESPONSE payload
    final payload = Uint8List(88 + 64);
    payload.setRange(0, 88, canonicalBytes);
    payload.setRange(88, 152, signature);

    return payload;
  }
}
