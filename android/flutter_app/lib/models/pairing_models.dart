import 'dart:convert';
import 'dart:typed_data';

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
  final String deviceId;       // Android phone UUID
  final String deviceName;     // Phone friendly name
  final String pcHostname;     // PC hostname
  final String pcIp;           // PC IP address
  final int pcPort;            // PC TLS port (8443)
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
