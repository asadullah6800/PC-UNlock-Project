import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../models/pc_device_model.dart';
import '../security/biometric_security_service.dart';
import '../services/service_locator.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final PcDeviceModel _activePc = const PcDeviceModel(
    deviceId: '123e4567-e89b-12d3-a456-426614174000',
    friendlyName: 'The-AK-PC',
    hostname: 'AK-PC-DESKTOP',
    ipAddress: '192.168.1.100',
    status: PcStatus.online,
  );

  String _phase4Status = 'Idle';
  String? _phase4SignatureHex;
  String? _keySecurityLevel;
  bool _isSigning = false;

  @override
  void initState() {
    super.initState();
    _loadKeyAndBiometricStatus();
  }

  Future<void> _loadKeyAndBiometricStatus() async {
    try {
      final keyStatus = await locator.biometricSecurityService.getKeyStatus();
      if (mounted) {
        setState(() {
          _keySecurityLevel = keyStatus.securityLevel;
        });
      }
    } catch (_) {}
  }

  Uint8List _generateTestCanonical88BytePayload({int sequence = 1}) {
    final buffer = Uint8List(88);
    final byteData = ByteData.sublistView(buffer);

    // ProtocolVersion = 0x0100 (2 bytes)
    byteData.setUint16(0, 0x0100, Endian.big);

    // ServerIdentity (16 bytes)
    for (int i = 0; i < 16; i++) {
      buffer[2 + i] = 0xAA;
    }

    // DeviceIdentity (16 bytes)
    for (int i = 0; i < 16; i++) {
      buffer[18 + i] = 0xBB;
    }

    // Operation = 0x0022 (AUTH_RESPONSE) (2 bytes)
    byteData.setUint16(34, 0x0022, Endian.big);

    // RequestID = sequence (4 bytes)
    byteData.setUint32(36, sequence, Endian.big);

    // SessionID = 1001 (8 bytes)
    byteData.setUint64(40, 1001, Endian.big);

    // Nonce (32 bytes)
    for (int i = 0; i < 32; i++) {
      buffer[48 + i] = (i + sequence) & 0xFF;
    }

    // Timestamp (8 bytes)
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    byteData.setUint64(80, nowMs, Endian.big);

    return buffer;
  }

  Future<void> _testBiometricSigning() async {
    setState(() {
      _isSigning = true;
      _phase4Status = 'Prompting for biometric...';
      _phase4SignatureHex = null;
    });

    try {
      // 1. Ensure key is ready
      final keyStatus = await locator.biometricSecurityService.ensureKeyReady();
      _keySecurityLevel = keyStatus.securityLevel;

      // 2. Generate canonical 88-byte payload
      final payload = _generateTestCanonical88BytePayload();

      // 3. Request biometric signature
      final signature = await locator.biometricSecurityService.signCanonicalMessage(payload);

      final hex = signature.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      if (mounted) {
        setState(() {
          _isSigning = false;
          _phase4Status = 'Signed Successfully (${signature.length} bytes, Hardware: $_keySecurityLevel)';
          _phase4SignatureHex = '${hex.substring(0, 16)}...${hex.substring(hex.length - 16)} (64 bytes)';
        });
      }
    } on BiometricSecurityException catch (e) {
      if (mounted) {
        setState(() {
          _isSigning = false;
          _phase4Status = 'Biometric Error: [${e.code}] ${e.message}';
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isSigning = false;
          _phase4Status = 'Error: $e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Mobile Fingerprint Unlock'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.pushNamed(context, '/settings');
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              elevation: 4,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(16),
              ),
              child: Padding(
                padding: const EdgeInsets.all(24.0),
                child: Column(
                  children: [
                    const Icon(
                      Icons.desktop_windows,
                      size: 64,
                      color: Colors.blueAccent,
                    ),
                    const SizedBox(height: 16),
                    Text(
                      _activePc.friendlyName,
                      style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Container(
                          width: 12,
                          height: 12,
                          decoration: const BoxDecoration(
                            color: Colors.green,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          'Status: ${_activePc.status.name.toUpperCase()}',
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                backgroundColor: Colors.blueAccent,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              icon: const Icon(Icons.fingerprint, size: 28, color: Colors.white),
              label: const Text(
                'Unlock PC',
                style: TextStyle(fontSize: 18, color: Colors.white),
              ),
              onPressed: () {
                locator.connectionService.sendUnlockRequest();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Unlock action queued (Phase 1 Foundation)')),
                );
              },
            ),
            const SizedBox(height: 16),
            OutlinedButton.icon(
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                side: const BorderSide(color: Colors.redAccent),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              icon: const Icon(Icons.lock_outline, size: 28, color: Colors.redAccent),
              label: const Text(
                'Lock PC',
                style: TextStyle(fontSize: 18, color: Colors.redAccent),
              ),
              onPressed: () {
                locator.connectionService.sendLockRequest();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Lock action queued (Phase 1 Foundation)')),
                );
              },
            ),
            const SizedBox(height: 24),
            // Isolated Phase 4 Biometric & Keystore Test Section
            Card(
              color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.4),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: BorderSide(color: Colors.blueAccent.withOpacity(0.3)),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.security, size: 20, color: Colors.blueAccent),
                        const SizedBox(width: 8),
                        const Text(
                          'Phase 4 Biometric Signing',
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                        ),
                        const Spacer(),
                        if (_keySecurityLevel != null)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                            decoration: BoxDecoration(
                              color: Colors.blue.withOpacity(0.2),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              _keySecurityLevel!,
                              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Text('Status: $_phase4Status', style: const TextStyle(fontSize: 13)),
                    if (_phase4SignatureHex != null) ...[
                      const SizedBox(height: 4),
                      Text(
                        'Sig: $_phase4SignatureHex',
                        style: const TextStyle(fontSize: 12, fontFamily: 'monospace', color: Colors.teal),
                      ),
                    ],
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        icon: _isSigning
                            ? const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : const Icon(Icons.fingerprint),
                        label: Text(_isSigning ? 'Signing...' : 'Test Fingerprint Signing (88B)'),
                        onPressed: _isSigning ? null : _testBiometricSigning,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
