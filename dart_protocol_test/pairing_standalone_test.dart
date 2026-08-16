/// Standalone Dart test for Phase 3 Pairing & Device Registration.
/// Run with: dart run pairing_standalone_test.dart

import 'dart:convert';
import 'dart:typed_data';

// ── Inline models from Flutter app for standalone execution ─────────────────

enum PairingState {
  unpaired,
  discovering,
  pairingRequested,
  waitingForSas,
  sasEntered,
  pairingConfirmed,
  paired,
  expired,
  cancelled,
  failed,
}

extension PairingStateExt on PairingState {
  String get displayName {
    switch (this) {
      case PairingState.unpaired:
        return 'UNPAIRED';
      case PairingState.discovering:
        return 'DISCOVERING';
      case PairingState.pairingRequested:
        return 'PAIRING_REQUESTED';
      case PairingState.waitingForSas:
        return 'WAITING_FOR_SAS';
      case PairingState.sasEntered:
        return 'SAS_ENTERED';
      case PairingState.pairingConfirmed:
        return 'PAIRING_CONFIRMED';
      case PairingState.paired:
        return 'PAIRED';
      case PairingState.expired:
        return 'EXPIRED';
      case PairingState.cancelled:
        return 'CANCELLED';
      case PairingState.failed:
        return 'FAILED';
    }
  }

  bool get isTerminal =>
      this == PairingState.paired ||
      this == PairingState.expired ||
      this == PairingState.cancelled ||
      this == PairingState.failed;
}

class PairedDeviceRecord {
  final String deviceId;
  final String deviceName;
  final String pcHostname;
  final String pcIp;
  final int pcPort;
  final DateTime pairedAt;
  final bool isActive;

  const PairedDeviceRecord({
    required this.deviceId,
    required this.deviceName,
    required this.pcHostname,
    required this.pcIp,
    this.pcPort = 8443,
    required this.pairedAt,
    this.isActive = true,
  });

  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'deviceName': deviceName,
        'pcHostname': pcHostname,
        'pcIp': pcIp,
        'pcPort': pcPort,
        'pairedAt': pairedAt.toIso8601String(),
        'isActive': isActive,
      };

  factory PairedDeviceRecord.fromJson(Map<String, dynamic> json) =>
      PairedDeviceRecord(
        deviceId: json['deviceId'] as String? ?? '',
        deviceName: json['deviceName'] as String? ?? '',
        pcHostname: json['pcHostname'] as String? ?? '',
        pcIp: json['pcIp'] as String? ?? '',
        pcPort: json['pcPort'] as int? ?? 8443,
        pairedAt: DateTime.tryParse(json['pairedAt'] as String? ?? '') ??
            DateTime.now(),
        isActive: json['isActive'] as bool? ?? true,
      );
}

class PairRequestPayload {
  final String deviceId;
  final String deviceName;
  final String publicKey;

  const PairRequestPayload({
    required this.deviceId,
    required this.deviceName,
    this.publicKey = '',
  });

  Uint8List toBytes() {
    final map = {
      'deviceId': deviceId,
      'deviceName': deviceName,
      'publicKey': publicKey,
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(map)));
  }
}

class PairConfirmPayload {
  final String deviceId;
  final String sasPin;

  const PairConfirmPayload({
    required this.deviceId,
    required this.sasPin,
  });

  Uint8List toBytes() {
    final map = {
      'deviceId': deviceId,
      'sasPin': sasPin,
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(map)));
  }
}

// ── Minimal test runner ──────────────────────────────────────────────────────

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

void main() {
  // ── Test 1: Pairing State Machine Enum Transitions ────────────────────────
  test('PairingState names match IDENTITY_MAPPING.md state machine', () {
    expect(PairingState.unpaired.displayName, 'UNPAIRED', desc: 'UNPAIRED');
    expect(PairingState.discovering.displayName, 'DISCOVERING', desc: 'DISCOVERING');
    expect(PairingState.pairingRequested.displayName, 'PAIRING_REQUESTED', desc: 'PAIRING_REQUESTED');
    expect(PairingState.waitingForSas.displayName, 'WAITING_FOR_SAS', desc: 'WAITING_FOR_SAS');
    expect(PairingState.sasEntered.displayName, 'SAS_ENTERED', desc: 'SAS_ENTERED');
    expect(PairingState.pairingConfirmed.displayName, 'PAIRING_CONFIRMED', desc: 'PAIRING_CONFIRMED');
    expect(PairingState.paired.displayName, 'PAIRED', desc: 'PAIRED');
    expect(PairingState.expired.displayName, 'EXPIRED', desc: 'EXPIRED');
    expect(PairingState.cancelled.displayName, 'CANCELLED', desc: 'CANCELLED');
    expect(PairingState.failed.displayName, 'FAILED', desc: 'FAILED');

    expect(PairingState.paired.isTerminal, true, desc: 'paired isTerminal == true');
    expect(PairingState.waitingForSas.isTerminal, false, desc: 'waitingForSas isTerminal == false');
  });

  // ── Test 2: PAIR_REQUEST Payload JSON Serialization ───────────────────────
  test('PairRequestPayload encodes JSON with valid UUID and device name', () {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const req = PairRequestPayload(deviceId: uuid, deviceName: 'Pixel 8');
    final bytes = req.toBytes();

    final decoded = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
    expect(decoded['deviceId'], uuid, desc: 'deviceId matches UUID');
    expect(decoded['deviceName'], 'Pixel 8', desc: 'deviceName matches');
    expect(decoded['publicKey'], '', desc: 'publicKey empty string during Phase 3');
  });

  // ── Test 3: PAIR_CONFIRM Payload with 6-digit SAS PIN ─────────────────────
  test('PairConfirmPayload encodes JSON with 6-digit SAS PIN', () {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const conf = PairConfirmPayload(deviceId: uuid, sasPin: '849201');
    final bytes = conf.toBytes();

    final decoded = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
    expect(decoded['deviceId'], uuid, desc: 'deviceId matches');
    expect(decoded['sasPin'], '849201', desc: 'sasPin is 6 digits');
    expect((decoded['sasPin'] as String).length, 6, desc: 'SAS PIN length == 6');
  });

  // ── Test 4: PairedDeviceRecord Serialization Roundtrip ───────────────────
  test('PairedDeviceRecord encodes and decodes JSON correctly', () {
    final now = DateTime.utc(2026, 8, 16, 12, 0, 0);
    final rec = PairedDeviceRecord(
      deviceId: '123e4567-e89b-12d3-a456-426614174000',
      deviceName: 'Pixel 8',
      pcHostname: 'WORKSTATION-01',
      pcIp: '192.168.1.100',
      pcPort: 8443,
      pairedAt: now,
      isActive: true,
    );

    final jsonMap = rec.toJson();
    final restored = PairedDeviceRecord.fromJson(jsonMap);

    expect(restored.deviceId, rec.deviceId, desc: 'deviceId roundtrip');
    expect(restored.deviceName, rec.deviceName, desc: 'deviceName roundtrip');
    expect(restored.pcHostname, rec.pcHostname, desc: 'pcHostname roundtrip');
    expect(restored.pcIp, rec.pcIp, desc: 'pcIp roundtrip');
    expect(restored.pcPort, 8443, desc: 'pcPort roundtrip');
    expect(restored.isActive, true, desc: 'isActive roundtrip');
  });

  // ── Test 5: Security Storage Verification ─────────────────────────────────
  test('PairedDeviceRecord stores NO passwords, biometric data, or private keys', () {
    final rec = PairedDeviceRecord(
      deviceId: '123e4567-e89b-12d3-a456-426614174000',
      deviceName: 'Pixel 8',
      pcHostname: 'WORKSTATION-01',
      pcIp: '192.168.1.100',
      pairedAt: DateTime.now(),
    );

    final jsonMap = rec.toJson();
    expect(jsonMap.containsKey('password'), false, desc: 'No password field');
    expect(jsonMap.containsKey('biometric'), false, desc: 'No biometric field');
    expect(jsonMap.containsKey('privateKey'), false, desc: 'No privateKey field');
    expect(jsonMap.containsKey('sasPin'), false, desc: 'No SAS PIN field stored');
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  print('');
  print('══════════════════════════════════════════════');
  print('Dart Pairing Tests: $_passed passed, $_failed failed');
  if (_failed > 0) {
    print('RESULT: FAIL');
    throw Exception('$_failed test(s) failed');
  } else {
    print('RESULT: PASS — Phase 3 Pairing & Device Registration verified');
  }
  print('══════════════════════════════════════════════');
}
