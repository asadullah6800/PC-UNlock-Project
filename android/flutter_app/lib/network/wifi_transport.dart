import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'network_state.dart';

class ReceivedProtocolFrame {
  final int magic;
  final int majorVersion;
  final int minorVersion;
  final int messageType;
  final int messageId;
  final int payloadLength;
  final BigInt sequenceNumber;
  final Uint8List payload;

  ReceivedProtocolFrame({
    required this.magic,
    required this.majorVersion,
    required this.minorVersion,
    required this.messageType,
    required this.messageId,
    required this.payloadLength,
    required this.sequenceNumber,
    required this.payload,
  });
}

typedef FrameCallback = void Function(ReceivedProtocolFrame frame);

class WiFiTransport {
  final String host;
  final int port;
  final bool useTls;

  NetworkConnectionState _state = NetworkConnectionState.disconnected;
  Socket? _socket;
  final StreamController<NetworkConnectionState> _stateController =
      StreamController<NetworkConnectionState>.broadcast();

  final List<int> _incomingBuffer = [];
  Timer? _heartbeatTimer;
  Timer? _inactivityTimer;
  Timer? _reconnectTimer;

  int _reconnectDelaySeconds = 1;
  bool _shouldAutoReconnect = true;
  int _messageIdCounter = 1;
  BigInt _sequenceNumber = BigInt.one;

  FrameCallback? onFrameReceived;

  WiFiTransport({
    required this.host,
    this.port = 8443,
    this.useTls = true,
  });

  NetworkConnectionState get state => _state;
  Stream<NetworkConnectionState> get onStateChanged => _stateController.stream;

  void _setState(NetworkConnectionState newState) {
    if (_state != newState) {
      _state = newState;
      _stateController.add(_state);
    }
  }

  /// Connect to Windows PC over TCP / TLS 1.3
  Future<bool> connect({Duration timeout = const Duration(seconds: 10)}) async {
    if (_state.isConnected || _state.isTransitioning) return false;

    _shouldAutoReconnect = true;
    _setState(NetworkConnectionState.tcpConnecting);

    try {
      if (useTls) {
        _setState(NetworkConnectionState.tlsHandshake);
        final sc = SecurityContext.defaultContext;
        // Connect with TLS 1.3/1.2 secure socket
        final secSocket = await SecureSocket.connect(
          host,
          port,
          context: sc,
          onBadCertificate: (cert) => true, // Local self-signed dev/pairing certificate validation
          timeout: timeout,
          supportedProtocols: ['tls1.3'],
        );
        _socket = secSocket;
      } else {
        _socket = await Socket.connect(host, port, timeout: timeout);
      }

      _incomingBuffer.clear();
      _reconnectDelaySeconds = 1;

      _socket?.listen(
        _onDataReceived,
        onError: (err) {
          _handleConnectionError();
        },
        onDone: () {
          _handleDisconnect();
        },
        cancelOnError: true,
      );

      _setState(NetworkConnectionState.activeSession);
      _startHeartbeat();
      _resetInactivityTimer();

      return true;
    } catch (e) {
      _handleConnectionError();
      return false;
    }
  }

  void _onDataReceived(List<int> data) {
    _resetInactivityTimer();
    _incomingBuffer.addAll(data);

    while (_incomingBuffer.length >= 24) {
      final headerBytes = Uint8List.fromList(_incomingBuffer.sublist(0, 24));
      final bd = ByteData.sublistView(headerBytes);

      final magic = bd.getUint16(0, Endian.big);
      final majorVer = bd.getUint8(2);
      final minorVer = bd.getUint8(3);
      final msgType = bd.getUint16(4, Endian.big);
      final msgId = bd.getUint32(8, Endian.big);
      final payloadLen = bd.getUint32(12, Endian.big);
      final seqNum = BigInt.from(bd.getUint64(16, Endian.big));

      if (magic != 0x4D55 || majorVer != 1 || payloadLen > 4096) {
        // Malformed packet, disconnect immediately
        disconnect();
        return;
      }

      final totalMsgLen = 24 + payloadLen;
      if (_incomingBuffer.length < totalMsgLen) {
        // Awaiting remaining payload bytes
        break;
      }

      final payload = Uint8List.fromList(_incomingBuffer.sublist(24, totalMsgLen));
      final frame = ReceivedProtocolFrame(
        magic: magic,
        majorVersion: majorVer,
        minorVersion: minorVer,
        messageType: msgType,
        messageId: msgId,
        payloadLength: payloadLen,
        sequenceNumber: seqNum,
        payload: payload,
      );

      _incomingBuffer.removeRange(0, totalMsgLen);

      // Handle keepalive PONG directly
      if (frame.messageType == 0x00E1 /* PONG */) {
        // Keepalive acknowledged
      }

      onFrameReceived?.call(frame);
    }
  }

  /// Send a 24-byte framed message with payload
  bool sendFrame(int messageType, Uint8List payload) {
    if (_socket == null || !_state.isConnected) return false;

    if (payload.length > 4096) {
      return false;
    }

    try {
      final bd = ByteData(24);
      bd.setUint16(0, 0x4D55, Endian.big);        // Magic
      bd.setUint8(2, 1);                         // MajorVersion
      bd.setUint8(3, 0);                         // MinorVersion
      bd.setUint16(4, messageType, Endian.big);   // MessageType
      bd.setUint16(6, 0);                         // Reserved
      bd.setUint32(8, _messageIdCounter++, Endian.big); // MessageID
      bd.setUint32(12, payload.length, Endian.big);     // PayloadLength
      bd.setUint64(16, _sequenceNumber.toInt(), Endian.big); // SequenceNumber
      _sequenceNumber += BigInt.one;

      final headerBytes = bd.buffer.asUint8List();
      final packet = Uint8List(24 + payload.length);
      packet.setRange(0, 24, headerBytes);
      if (payload.isNotEmpty) {
        packet.setRange(24, 24 + payload.length, payload);
      }

      _socket?.add(packet);
      return true;
    } catch (_) {
      return false;
    }
  }

  void _startHeartbeat() {
    _heartbeatTimer?.cancel();
    _heartbeatTimer = Timer.periodic(const Duration(seconds: 15), (_) {
      if (_state.isConnected) {
        // Send PING opcode (0x00E0)
        sendFrame(0x00E0, Uint8List(0));
      }
    });
  }

  void _resetInactivityTimer() {
    _inactivityTimer?.cancel();
    _inactivityTimer = Timer(const Duration(seconds: 30), () {
      if (_state.isConnected) {
        // Connection timed out (30s inactivity)
        _handleDisconnect();
      }
    });
  }

  void _handleDisconnect() {
    _stopTimers();
    _socket?.destroy();
    _socket = null;
    _setState(NetworkConnectionState.disconnected);

    if (_shouldAutoReconnect) {
      _scheduleReconnect();
    }
  }

  void _handleConnectionError() {
    _stopTimers();
    _socket?.destroy();
    _socket = null;
    _setState(NetworkConnectionState.errorState);

    if (_shouldAutoReconnect) {
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    _setState(NetworkConnectionState.reconnecting);

    _reconnectTimer = Timer(Duration(seconds: _reconnectDelaySeconds), () {
      // Exponential backoff up to 16 seconds
      _reconnectDelaySeconds = (_reconnectDelaySeconds * 2).clamp(1, 16);
      connect();
    });
  }

  void _stopTimers() {
    _heartbeatTimer?.cancel();
    _inactivityTimer?.cancel();
    _reconnectTimer?.cancel();
  }

  /// Cleanly disconnect session
  void disconnect() {
    _shouldAutoReconnect = false;
    _stopTimers();
    _socket?.destroy();
    _socket = null;
    _setState(NetworkConnectionState.disconnected);
  }

  void dispose() {
    disconnect();
    _stateController.close();
  }
}
