import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

class DiscoveredPcEndpoint {
  final String hostName;
  final String ipAddress;
  final int port;
  final int state;
  final String serviceType;
  final DateTime lastSeen;

  const DiscoveredPcEndpoint({
    required this.hostName,
    required this.ipAddress,
    required this.port,
    required this.state,
    required this.serviceType,
    required this.lastSeen,
  });

  factory DiscoveredPcEndpoint.fromJson(Map<String, dynamic> json, String sourceIp) {
    return DiscoveredPcEndpoint(
      hostName: json['host'] as String? ?? 'Unknown',
      ipAddress: sourceIp,
      port: json['port'] as int? ?? 8443,
      state: json['state'] as int? ?? 0,
      serviceType: json['service'] as String? ?? '_mobileunlock._tcp.local.',
      lastSeen: DateTime.now(),
    );
  }

  @override
  String toString() => 'DiscoveredPcEndpoint(host: $hostName, ip: $ipAddress:$port, state: $state)';
}

class MdnsDiscovery {
  final int discoveryPort;
  RawDatagramSocket? _socket;
  final StreamController<List<DiscoveredPcEndpoint>> _endpointsController =
      StreamController<List<DiscoveredPcEndpoint>>.broadcast();

  final Map<String, DiscoveredPcEndpoint> _discovered = {};
  bool _isSearching = false;

  MdnsDiscovery({this.discoveryPort = 8444});

  Stream<List<DiscoveredPcEndpoint>> get onEndpointsChanged => _endpointsController.stream;
  List<DiscoveredPcEndpoint> get currentEndpoints => _discovered.values.toList();
  bool get isSearching => _isSearching;

  /// Start active discovery broadcast
  Future<void> startDiscovery({Duration timeout = const Duration(seconds: 5)}) async {
    if (_isSearching) return;
    _isSearching = true;
    _discovered.clear();
    _endpointsController.add([]);

    try {
      _socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      _socket?.broadcastEnabled = true;

      _socket?.listen((RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          final dg = _socket?.receive();
          if (dg != null) {
            _handleDatagram(dg);
          }
        }
      });

      // Send discovery query
      _broadcastQuery();

      // Repeat query after 1.5s
      Timer(const Duration(milliseconds: 1500), () {
        if (_isSearching) _broadcastQuery();
      });

      // Auto-stop after timeout
      Timer(timeout, () {
        stopDiscovery();
      });
    } catch (e) {
      stopDiscovery();
    }
  }

  void _broadcastQuery() {
    if (_socket == null) return;
    try {
      // 24-byte FrameHeader with DISCOVER opcode (0x0001)
      final bd = ByteData(24);
      bd.setUint16(0, 0x4D55, Endian.big); // Magic
      bd.setUint8(2, 1);                  // MajorVersion
      bd.setUint8(3, 0);                  // MinorVersion
      bd.setUint16(4, 0x0001, Endian.big); // DISCOVER opcode
      bd.setUint16(6, 0);                  // Reserved
      bd.setUint32(8, 1, Endian.big);      // MessageID
      bd.setUint32(12, 0, Endian.big);     // PayloadLength
      bd.setUint64(16, 1, Endian.big);     // SequenceNumber

      final queryBytes = bd.buffer.asUint8List();
      _socket?.send(queryBytes, InternetAddress('255.255.255.255'), discoveryPort);
    } catch (_) {}
  }

  void _handleDatagram(Datagram dg) {
    try {
      final bytes = dg.data;
      if (bytes.length < 24) return;

      final bd = ByteData.sublistView(bytes);
      final magic = bd.getUint16(0, Endian.big);
      final majorVer = bd.getUint8(2);
      final msgType = bd.getUint16(4, Endian.big);
      final payloadLen = bd.getUint32(12, Endian.big);

      if (magic != 0x4D55 || majorVer != 1 || msgType != 0x0002 /* DISCOVERY_RESPONSE */) {
        return;
      }

      if (bytes.length < 24 + payloadLen || payloadLen == 0 || payloadLen > 4096) {
        return;
      }

      final payloadStr = utf8.decode(bytes.sublist(24, 24 + payloadLen));
      final jsonMap = jsonDecode(payloadStr) as Map<String, dynamic>;

      final endpoint = DiscoveredPcEndpoint.fromJson(jsonMap, dg.address.address);
      final key = '${endpoint.ipAddress}:${endpoint.port}';

      _discovered[key] = endpoint;
      _endpointsController.add(_discovered.values.toList());
    } catch (_) {
      // Ignore malformed datagrams
    }
  }

  void stopDiscovery() {
    _isSearching = false;
    _socket?.close();
    _socket = null;
  }

  void dispose() {
    stopDiscovery();
    _endpointsController.close();
  }
}
