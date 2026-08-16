import 'package:flutter/material.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _requireFingerprintForLock = false;
  bool _enableBleDiscovery = true;
  bool _enableAutoConnect = true;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text('Require Fingerprint for Remote Lock'),
            subtitle: const Text('Require biometric authentication before sending Lock PC request'),
            value: _requireFingerprintForLock,
            onChanged: (val) {
              setState(() => _requireFingerprintForLock = val);
            },
          ),
          const Divider(),
          SwitchListTile(
            title: const Text('Enable Bluetooth (BLE) Discovery'),
            subtitle: const Text('Use BLE proximity hint for automatic discovery'),
            value: _enableBleDiscovery,
            onChanged: (val) {
              setState(() => _enableBleDiscovery = val);
            },
          ),
          const Divider(),
          SwitchListTile(
            title: const Text('Auto-Connect to Paired PC'),
            subtitle: const Text('Connect automatically when on local Wi-Fi'),
            value: _enableAutoConnect,
            onChanged: (val) {
              setState(() => _enableAutoConnect = val);
            },
          ),
          const Divider(),
          ListTile(
            title: const Text('Paired Devices'),
            subtitle: const Text('Manage trusted Windows workstations'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              // Open paired devices screen
            },
          ),
        ],
      ),
    );
  }
}
