import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../models/pairing_models.dart';
import '../network/wifi_transport.dart';

class PairingService {
  final WiFiTransport _transport;
  PairingState _state = PairingState.unpaired;
  final _stateController = StreamController<PairingState>.broadcast();
  PairedDeviceRecord? _pairedRecord;

  String? _currentDeviceId;
  String? _currentDeviceName;
  String? _currentPcHost;
  int _currentPcPort = 8443;
  Timer? _sasTimer;

  PairingService({WiFiTransport? transport})
      : _transport = transport ?? WiFiTransport() {
    _transport.onFrameReceived = _onFrameReceived;
  }

  Stream<PairingState> get stateStream => _stateController.stream;
  PairingState get state => _state;
  PairedDeviceRecord? get pairedDevice => _pairedRecord;

  void _setState(PairingState newState) {
    _state = newState;
    _stateController.add(newState);
  }

  /// Initiates pairing with a discovered PC endpoint
  Future<bool> startPairing({
    required String pcHost,
    required int pcPort,
    required String deviceId,
    required String deviceName,
  }) async {
    _currentDeviceId = deviceId;
    _currentDeviceName = deviceName;
    _currentPcHost = pcHost;
    _currentPcPort = pcPort;

    _setState(PairingState.pairingRequested);

    final connected = await _transport.connect(
      host: pcHost,
      port: pcPort,
      useTls: true,
      timeout: const Duration(seconds: 10),
    );

    if (!connected) {
      _setState(PairingState.failed);
      return false;
    }

    // Send PAIR_REQUEST (0x0010)
    final req = PairRequestPayload(
      deviceId: deviceId,
      deviceName: deviceName,
    );

    final sent = _transport.sendFrame(0x0010, req.toBytes());
    if (!sent) {
      _setState(PairingState.failed);
      return false;
    }

    _setState(PairingState.waitingForSas);

    // 60-second SAS timeout
    _sasTimer?.cancel();
    _sasTimer = Timer(const Duration(seconds: 60), () {
      if (_state == PairingState.waitingForSas ||
          _state == PairingState.sasEntered) {
        cancelPairing('SAS PIN timeout');
      }
    });

    return true;
  }

  /// Submits the user-entered 6-digit SAS PIN to the PC
  bool submitSasPin(String pin) {
    if (_state != PairingState.waitingForSas) return false;
    if (pin.length != 6) return false;
    if (_currentDeviceId == null) return false;

    _setState(PairingState.sasEntered);

    final confirm = PairConfirmPayload(
      deviceId: _currentDeviceId!,
      sasPin: pin,
    );

    // Send PAIR_CONFIRM (0x0012)
    return _transport.sendFrame(0x0012, confirm.toBytes());
  }

  /// Cancels the current pairing session
  void cancelPairing([String? reason]) {
    _sasTimer?.cancel();
    _transport.disconnect();
    _setState(PairingState.cancelled);
  }

  /// Unpairs the current device from the PC
  Future<bool> unpairDevice() async {
    if (_pairedRecord == null) return true;

    final connected = await _transport.connect(
      host: _pairedRecord!.pcIp,
      port: _pairedRecord!.pcPort,
      useTls: true,
    );

    if (connected) {
      final unpairPayload = Uint8List.fromList(
        utf8.encode(jsonEncode({'deviceId': _pairedRecord!.deviceId})),
      );
      // Send UNPAIR_REQUEST (0x0050)
      _transport.sendFrame(0x0050, unpairPayload);
      await Future.delayed(const Duration(milliseconds: 300));
      _transport.disconnect();
    }

    _pairedRecord = null;
    _setState(PairingState.unpaired);
    return true;
  }

  void _onFrameReceived(ReceivedProtocolFrame frame) {
    if (frame.messageType == 0x0011 /* PAIR_RESPONSE */) {
      _setState(PairingState.waitingForSas);
    } else if (frame.messageType == 0x0013 /* PAIR_COMPLETE */) {
      _sasTimer?.cancel();
      _setState(PairingState.pairingConfirmed);

      _pairedRecord = PairedDeviceRecord(
        deviceId: _currentDeviceId ?? '',
        deviceName: _currentDeviceName ?? '',
        pcHostname: _currentPcHost ?? 'PC',
        pcIp: _currentPcHost ?? '127.0.0.1',
        pcPort: _currentPcPort,
        pairedAt: DateTime.now(),
        isActive: true,
      );

      _setState(PairingState.paired);
    } else if (frame.messageType == 0x00FF /* PROTO_ERROR */) {
      _sasTimer?.cancel();
      _setState(PairingState.failed);
      _transport.disconnect();
    } else if (frame.messageType == 0x0051 /* UNPAIR_RESPONSE */) {
      _pairedRecord = null;
      _setState(PairingState.unpaired);
    }
  }

  void dispose() {
    _sasTimer?.cancel();
    _transport.dispose();
    _stateController.close();
  }
}
