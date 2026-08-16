/// Connection state machine enum matching NETWORKING.md specification.
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
  bool get isTransitioning =>
      this == NetworkConnectionState.discovering ||
      this == NetworkConnectionState.tcpConnecting ||
      this == NetworkConnectionState.tlsHandshake ||
      this == NetworkConnectionState.reconnecting;
}
