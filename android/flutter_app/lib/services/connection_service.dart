import 'dart:async';
import '../models/pc_device_model.dart';
import 'logging_service.dart';

abstract class IConnectionService {
  Stream<PcStatus> get statusStream;
  Future<bool> connect(PcDeviceModel device);
  Future<void> disconnect();
  Future<bool> sendLockRequest();
  Future<bool> sendUnlockRequest();
}

class MockConnectionService implements IConnectionService {
  final _statusController = StreamController<PcStatus>.broadcast();
  PcStatus _currentStatus = PcStatus.offline;

  MockConnectionService() {
    _statusController.add(_currentStatus);
  }

  @override
  Stream<PcStatus> get statusStream => _statusController.stream;

  @override
  Future<bool> connect(PcDeviceModel device) async {
    LoggingService.info('Connecting to ${device.friendlyName} (${device.ipAddress}:${device.port})...');
    _currentStatus = PcStatus.online;
    _statusController.add(_currentStatus);
    return true;
  }

  @override
  Future<void> disconnect() async {
    LoggingService.info('Disconnecting from active PC session...');
    _currentStatus = PcStatus.offline;
    _statusController.add(_currentStatus);
  }

  @override
  Future<bool> sendLockRequest() async {
    LoggingService.info('Lock request queued (Phase 1 Foundation - No authentication executed)');
    return true;
  }

  @override
  Future<bool> sendUnlockRequest() async {
    LoggingService.info('Unlock request queued (Phase 1 Foundation - No authentication executed)');
    return true;
  }

  void dispose() {
    _statusController.close();
  }
}
