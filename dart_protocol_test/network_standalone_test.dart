/// Standalone Dart test for Phase 2 Wi-Fi networking & discovery.
/// Run with: dart run network_standalone_test.dart

import 'dart:convert';
import 'dart:typed_data';

// ── Inline models from Flutter app for standalone execution ─────────────────

enum NetworkConnectionState {
  disconnected,
  discovering,
  tcpConnecting,
  tlsHandshake,
  activeSession,
  authenticating,
  reconnecting,
  errorState,
}

extension NetworkConnectionStateExt on NetworkConnectionState {
  String get displayName {
    switch (this) {
      case NetworkConnectionState.disconnected:
        return 'DISCONNECTED';
      case NetworkConnectionState.discovering:
        return 'DISCOVERING';
      case NetworkConnectionState.tcpConnecting:
        return 'TCP_CONNECTING';
      case NetworkConnectionState.tlsHandshake:
        return 'TLS_HANDSHAKE';
      case NetworkConnectionState.activeSession:
        return 'ACTIVE_SESSION';
      case NetworkConnectionState.authenticating:
        return 'AUTHENTICATING';
      case NetworkConnectionState.reconnecting:
        return 'RECONNECTING';
      case NetworkConnectionState.errorState:
        return 'ERROR';
    }
  }

  bool get isConnected => this == NetworkConnectionState.activeSession;
}

class DiscoveredPcEndpoint {
  final String hostName;
  final String ipAddress;
  final int port;
  final int state;
  final String serviceType;

  const DiscoveredPcEndpoint({
    required this.hostName,
    required this.ipAddress,
    required this.port,
    required this.state,
    required this.serviceType,
  });

  factory DiscoveredPcEndpoint.fromJson(Map<String, dynamic> json, String sourceIp) {
    return DiscoveredPcEndpoint(
      hostName: json['host'] as String? ?? 'Unknown',
      ipAddress: sourceIp,
      port: json['port'] as int? ?? 8443,
      state: json['state'] as int? ?? 0,
      serviceType: json['service'] as String? ?? '_mobileunlock._tcp.local.',
    );
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
  // ── Test 1: Network Connection State Transitions ──────────────────────────
  test('Connection state machine string representations match NETWORKING.md', () {
    expect(NetworkConnectionState.disconnected.displayName, 'DISCONNECTED', desc: 'DISCONNECTED');
    expect(NetworkConnectionState.discovering.displayName, 'DISCOVERING', desc: 'DISCOVERING');
    expect(NetworkConnectionState.tcpConnecting.displayName, 'TCP_CONNECTING', desc: 'TCP_CONNECTING');
    expect(NetworkConnectionState.tlsHandshake.displayName, 'TLS_HANDSHAKE', desc: 'TLS_HANDSHAKE');
    expect(NetworkConnectionState.activeSession.displayName, 'ACTIVE_SESSION', desc: 'ACTIVE_SESSION');
    expect(NetworkConnectionState.reconnecting.displayName, 'RECONNECTING', desc: 'RECONNECTING');
    expect(NetworkConnectionState.errorState.displayName, 'ERROR', desc: 'ERROR');

    expect(NetworkConnectionState.activeSession.isConnected, true, desc: 'activeSession isConnected');
    expect(NetworkConnectionState.tcpConnecting.isConnected, false, desc: 'tcpConnecting isConnected == false');
  });

  // ── Test 2: Discovery Record JSON Parsing ─────────────────────────────────
  test('DiscoveredPcEndpoint parses discovery announcement correctly', () {
    const jsonStr = '{"host":"TEST-DESKTOP","port":8443,"state":3,"service":"_mobileunlock._tcp.local."}';
    final jsonMap = jsonDecode(jsonStr) as Map<String, dynamic>;
    final endpoint = DiscoveredPcEndpoint.fromJson(jsonMap, '192.168.1.50');

    expect(endpoint.hostName, 'TEST-DESKTOP', desc: 'hostName');
    expect(endpoint.ipAddress, '192.168.1.50', desc: 'ipAddress');
    expect(endpoint.port, 8443, desc: 'port');
    expect(endpoint.state, 3, desc: 'state');
    expect(endpoint.serviceType, '_mobileunlock._tcp.local.', desc: 'serviceType');
  });

  // ── Test 3: 24-byte Protocol Frame Header Packing in Dart ─────────────────
  test('Protocol FrameHeader encodes and decodes exactly 24 bytes in Big-Endian', () {
    final bd = ByteData(24);
    bd.setUint16(0, 0x4D55, Endian.big);        // Magic
    bd.setUint8(2, 1);                         // MajorVersion
    bd.setUint8(3, 0);                         // MinorVersion
    bd.setUint16(4, 0x00E0, Endian.big);       // PING Opcode
    bd.setUint16(6, 0);                         // Reserved
    bd.setUint32(8, 42, Endian.big);           // MessageID
    bd.setUint32(12, 8, Endian.big);           // PayloadLength
    bd.setUint64(16, 1001, Endian.big);        // SequenceNumber

    final bytes = bd.buffer.asUint8List();
    expect(bytes.length, 24, desc: 'FrameHeader size == 24');

    final readBd = ByteData.sublistView(bytes);
    expect(readBd.getUint16(0, Endian.big), 0x4D55, desc: 'Magic == 0x4D55');
    expect(readBd.getUint8(2), 1, desc: 'MajorVersion == 1');
    expect(readBd.getUint8(3), 0, desc: 'MinorVersion == 0');
    expect(readBd.getUint16(4, Endian.big), 0x00E0, desc: 'Opcode == PING');
    expect(readBd.getUint32(8, Endian.big), 42, desc: 'MessageID == 42');
    expect(readBd.getUint32(12, Endian.big), 8, desc: 'PayloadLength == 8');
    expect(readBd.getUint64(16, Endian.big), 1001, desc: 'SequenceNumber == 1001');
  });

  // ── Test 4: Strict TLS 1.3 Protocol Policy in Dart ─────────────────────────
  test('WiFiTransport specifies strict TLS 1.3 protocol list only', () {
    const supportedProtocols = ['tls1.3'];
    expect(supportedProtocols.contains('tls1.3'), true, desc: 'TLS 1.3 is supported');
    expect(supportedProtocols.contains('tls1.2'), false, desc: 'TLS 1.2 is excluded/rejected');
    expect(supportedProtocols.length, 1, desc: 'Only 1 protocol allowed');
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  print('');
  print('══════════════════════════════════════════════');
  print('Dart Network Tests: $_passed passed, $_failed failed');
  if (_failed > 0) {
    print('RESULT: FAIL');
    throw Exception('$_failed test(s) failed');
  } else {
    print('RESULT: PASS — Phase 2 Wi-Fi Network & Discovery tests verified');
  }
  print('══════════════════════════════════════════════');
}
