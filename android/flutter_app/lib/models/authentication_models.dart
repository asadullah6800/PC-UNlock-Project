import 'dart:typed_data';

class AuthChallenge {
  final int sessionId;
  final Uint8List nonce;
  final Uint8List serverIdentity;
  final int timestamp;

  AuthChallenge({
    required this.sessionId,
    required this.nonce,
    required this.serverIdentity,
    required this.timestamp,
  });

  factory AuthChallenge.fromJson(Map<String, dynamic> json) {
    return AuthChallenge(
      sessionId: json['sessionId'] as int,
      nonce: _hexToBytes(json['nonce'] as String),
      serverIdentity: _hexToBytes(json['serverIdentity'] as String),
      timestamp: json['timestamp'] as int,
    );
  }

  static Uint8List _hexToBytes(String hex) {
    final bytes = <int>[];
    for (int i = 0; i < hex.length; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(bytes);
  }
}

class AuthResult {
  final bool success;
  final String? accountSid;
  final String? errorMessage;

  AuthResult({
    required this.success,
    this.accountSid,
    this.errorMessage,
  });
}
