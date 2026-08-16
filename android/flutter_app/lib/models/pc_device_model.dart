import 'dart:typed_data';

enum PcStatus {
  unknown,
  offline,
  online,
  locked,
  unlocked,
  suspended,
  sleeping,
  pairing,
  authenticating,
  error
}

class PcDeviceModel {
  final String deviceId; // UUID string representation
  final String friendlyName;
  final String hostname;
  final String ipAddress;
  final int port;
  final PcStatus status;
  final Uint8List? publicKeyBytes;

  const PcDeviceModel({
    required this.deviceId,
    required this.friendlyName,
    required this.hostname,
    required this.ipAddress,
    this.port = 8443,
    this.status = PcStatus.unknown,
    this.publicKeyBytes,
  });

  PcDeviceModel copyWith({
    String? deviceId,
    String? friendlyName,
    String? hostname,
    String? ipAddress,
    int? port,
    PcStatus? status,
    Uint8List? publicKeyBytes,
  }) {
    return PcDeviceModel(
      deviceId: deviceId ?? this.deviceId,
      friendlyName: friendlyName ?? this.friendlyName,
      hostname: hostname ?? this.hostname,
      ipAddress: ipAddress ?? this.ipAddress,
      port: port ?? this.port,
      status: status ?? this.status,
      publicKeyBytes: publicKeyBytes ?? this.publicKeyBytes,
    );
  }
}
