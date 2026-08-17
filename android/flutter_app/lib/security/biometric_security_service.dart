import 'dart:typed_data';
import 'package:flutter/services.dart';

/// Exceptions for Biometric Security Subsystem
class BiometricSecurityException implements Exception {
  final String code;
  final String message;
  const BiometricSecurityException(this.code, this.message);

  @override
  String toString() => 'BiometricSecurityException($code): $message';
}

class InvalidPayloadException extends BiometricSecurityException {
  const InvalidPayloadException(String message) : super('INVALID_PAYLOAD', message);
}

class BiometricCancelledException extends BiometricSecurityException {
  const BiometricCancelledException([String message = 'User cancelled biometric prompt'])
      : super('BIOMETRIC_CANCELLED', message);
}

class BiometricNotEnrolledException extends BiometricSecurityException {
  const BiometricNotEnrolledException([String message = 'No biometrics enrolled on device'])
      : super('BIOMETRIC_NOT_ENROLLED', message);
}

class BiometricUnavailableException extends BiometricSecurityException {
  const BiometricUnavailableException(String message) : super('BIOMETRIC_UNAVAILABLE', message);
}

class BiometricLockoutException extends BiometricSecurityException {
  const BiometricLockoutException(String message) : super('BIOMETRIC_LOCKOUT', message);
}

class KeyInvalidatedException extends BiometricSecurityException {
  const KeyInvalidatedException([String message = 'Key invalidated due to new biometric enrollment'])
      : super('KEY_INVALIDATED', message);
}

class KeyNotFoundException extends BiometricSecurityException {
  const KeyNotFoundException([String message = 'Device key not found in Keystore'])
      : super('KEY_NOT_FOUND', message);
}

class KeyGenerationException extends BiometricSecurityException {
  const KeyGenerationException(String message) : super('KEY_GENERATION_FAILED', message);
}

class SignatureFailedException extends BiometricSecurityException {
  const SignatureFailedException(String message) : super('SIGNATURE_FAILED', message);
}

class InvalidSignatureException extends BiometricSecurityException {
  const InvalidSignatureException(String message) : super('INVALID_SIGNATURE_FORMAT', message);
}

/// Status model for Keystore device key
class KeyStatus {
  final bool exists;
  final String securityLevel; // 'STRONGBOX', 'TEE', 'SOFTWARE', 'NONE', 'UNKNOWN'
  final bool isInvalidated;

  const KeyStatus({
    required this.exists,
    required this.securityLevel,
    required this.isInvalidated,
  });

  factory KeyStatus.fromMap(Map<dynamic, dynamic> map) {
    return KeyStatus(
      exists: map['exists'] == true,
      securityLevel: map['securityLevel'] as String? ?? 'UNKNOWN',
      isInvalidated: map['isInvalidated'] == true,
    );
  }

  @override
  String toString() => 'KeyStatus(exists: $exists, securityLevel: $securityLevel, isInvalidated: $isInvalidated)';
}

/// Status model for Biometric capability
class BiometricCapability {
  final bool available;
  final String status; // 'SUCCESS', 'NONE_ENROLLED', 'NO_HARDWARE', 'HW_UNAVAILABLE', etc.

  const BiometricCapability({
    required this.available,
    required this.status,
  });

  factory BiometricCapability.fromMap(Map<dynamic, dynamic> map) {
    return BiometricCapability(
      available: map['available'] == true,
      status: map['status'] as String? ?? 'UNKNOWN',
    );
  }

  @override
  String toString() => 'BiometricCapability(available: $available, status: $status)';
}

/// Service providing typed access to the Android Biometric Keystore subsystem via MethodChannel.
class BiometricSecurityService {
  static const String channelName = 'com.mobileunlock.security/biometrics';
  final MethodChannel _channel;

  BiometricSecurityService({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(channelName);

  /// Checks if Strong Biometric authentication is available and enrolled.
  Future<BiometricCapability> checkBiometricCapability() async {
    try {
      final result = await _channel.invokeMethod<Map<dynamic, dynamic>>('isBiometricAvailable');
      if (result == null) {
        return const BiometricCapability(available: false, status: 'UNKNOWN');
      }
      return BiometricCapability.fromMap(result);
    } on PlatformException catch (e) {
      throw _mapPlatformException(e);
    }
  }

  /// Checks if StrongBox hardware keystore is supported on this device.
  Future<bool> isStrongBoxSupported() async {
    try {
      final result = await _channel.invokeMethod<bool>('isStrongBoxSupported');
      return result ?? false;
    } on PlatformException catch (e) {
      throw _mapPlatformException(e);
    }
  }

  /// Queries the current status of the Keystore device identity key.
  Future<KeyStatus> getKeyStatus() async {
    try {
      final result = await _channel.invokeMethod<Map<dynamic, dynamic>>('getKeyStatus');
      if (result == null) {
        return const KeyStatus(exists: false, securityLevel: 'UNKNOWN', isInvalidated: false);
      }
      return KeyStatus.fromMap(result);
    } on PlatformException catch (e) {
      throw _mapPlatformException(e);
    }
  }

  /// Ensures the hardware-backed key pair exists, generating it if necessary.
  /// Does NOT silently overwrite an existing valid key.
  Future<KeyStatus> ensureKeyReady() async {
    try {
      final result = await _channel.invokeMethod<Map<dynamic, dynamic>>('ensureKeyReady');
      if (result == null) {
        throw const KeyGenerationException('Null response from ensureKeyReady');
      }
      return KeyStatus.fromMap(result);
    } on PlatformException catch (e) {
      throw _mapPlatformException(e);
    }
  }

  /// Retrieves the X.509 encoded bytes of the public key.
  Future<Uint8List?> getPublicKey() async {
    try {
      final result = await _channel.invokeMethod<Uint8List>('getPublicKey');
      return result;
    } on PlatformException catch (e) {
      if (e.code == 'KEY_NOT_FOUND') return null;
      throw _mapPlatformException(e);
    }
  }

  /// Requests user biometric authorization and produces a 64-byte IEEE P1363 (r || s)
  /// signature over the exact 88-byte canonical SignedMessage payload.
  Future<Uint8List> signCanonicalMessage(
    Uint8List canonicalPayload88Bytes, {
    String title = 'Authorize Workstation Unlock',
    String subtitle = 'Scan your fingerprint to sign unlock challenge',
  }) async {
    if (canonicalPayload88Bytes.length != 88) {
      throw InvalidPayloadException(
        'Canonical payload must be exactly 88 bytes, got ${canonicalPayload88Bytes.length}',
      );
    }

    try {
      final signature = await _channel.invokeMethod<Uint8List>('signCanonicalMessage', {
        'payload': canonicalPayload88Bytes,
        'title': title,
        'subtitle': subtitle,
      });

      if (signature == null) {
        throw const SignatureFailedException('Null signature returned from platform channel');
      }

      if (signature.length != 64) {
        throw InvalidSignatureException(
          'Signature must be exactly 64 bytes IEEE P1363, got ${signature.length}',
        );
      }

      return signature;
    } on PlatformException catch (e) {
      throw _mapPlatformException(e);
    }
  }

  BiometricSecurityException _mapPlatformException(PlatformException e) {
    final msg = e.message ?? e.details?.toString() ?? 'Unknown platform error';
    switch (e.code) {
      case 'INVALID_PAYLOAD':
        return InvalidPayloadException(msg);
      case 'BIOMETRIC_CANCELLED':
        return BiometricCancelledException(msg);
      case 'BIOMETRIC_NOT_ENROLLED':
        return BiometricNotEnrolledException(msg);
      case 'BIOMETRIC_UNAVAILABLE':
        return BiometricUnavailableException(msg);
      case 'BIOMETRIC_LOCKOUT':
        return BiometricLockoutException(msg);
      case 'KEY_INVALIDATED':
        return KeyInvalidatedException(msg);
      case 'KEY_NOT_FOUND':
        return KeyNotFoundException(msg);
      case 'KEY_GENERATION_FAILED':
        return KeyGenerationException(msg);
      case 'SIGNATURE_FAILED':
        return SignatureFailedException(msg);
      case 'INVALID_SIGNATURE_FORMAT':
        return InvalidSignatureException(msg);
      default:
        return BiometricSecurityException(e.code, msg);
    }
  }
}
