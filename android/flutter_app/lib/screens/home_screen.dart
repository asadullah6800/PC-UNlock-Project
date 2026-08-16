import 'package:flutter/material.dart';
import '../models/pc_device_model.dart';
import '../services/service_locator.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  PcDeviceModel _activePc = const PcDeviceModel(
    deviceId: '123e4567-e89b-12d3-a456-426614174000',
    friendlyName: 'The-AK-PC',
    hostname: 'AK-PC-DESKTOP',
    ipAddress: '192.168.1.100',
    status: PcStatus.online,
  );

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
      body: Padding(
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
            const SizedBox(height: 32),
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
          ],
        ),
      ),
    );
  }
}
