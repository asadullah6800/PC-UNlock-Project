import 'package:flutter/material.dart';
import '../models/pairing_models.dart';
import '../services/pairing_service.dart';

class PairingScreen extends StatefulWidget {
  final PairingService pairingService;
  final String targetPcHost;
  final int targetPcPort;
  final String deviceId;
  final String deviceName;

  const PairingScreen({
    super.key,
    required this.pairingService,
    required this.targetPcHost,
    this.targetPcPort = 8443,
    required this.deviceId,
    required this.deviceName,
  });

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  final TextEditingController _pinController = TextEditingController();
  PairingState _currentState = PairingState.unpaired;
  String _errorMessage = '';

  @override
  void initState() {
    super.initState();
    widget.pairingService.stateStream.listen((state) {
      if (mounted) {
        setState(() {
          _currentState = state;
          if (state == PairingState.failed) {
            _errorMessage = 'Pairing failed. Incorrect PIN or connection error.';
          } else if (state == PairingState.expired) {
            _errorMessage = 'Pairing timed out (60s). Please try again.';
          }
        });
      }
    });

    _startPairing();
  }

  Future<void> _startPairing() async {
    setState(() {
      _errorMessage = '';
    });
    await widget.pairingService.startPairing(
      pcHost: widget.targetPcHost,
      pcPort: widget.targetPcPort,
      deviceId: widget.deviceId,
      deviceName: widget.deviceName,
    );
  }

  void _submitPin() {
    final pin = _pinController.text.trim();
    if (pin.length != 6) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter a 6-digit numeric PIN')),
      );
      return;
    }
    widget.pairingService.submitSasPin(pin);
  }

  @override
  void dispose() {
    _pinController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Pair with PC'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () {
            widget.pairingService.cancelPairing('User navigated back');
            Navigator.of(context).pop();
          },
        ),
      ),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Center(
          child: SingleChildScrollView(
            child: _buildBody(),
          ),
        ),
      ),
    );
  }

  Widget _buildBody() {
    switch (_currentState) {
      case PairingState.unpaired:
      case PairingState.pairingRequested:
        return Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 24),
            Text(
              'Connecting to ${widget.targetPcHost}...',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text('Establishing secure TLS 1.3 session'),
          ],
        );

      case PairingState.waitingForSas:
      case PairingState.sasEntered:
        return Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Icon(Icons.security, size: 64, color: Colors.blue),
            const SizedBox(height: 16),
            Text(
              'Verify SAS PIN',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            const Text(
              'Enter the 6-digit Short Authentication String (SAS) PIN displayed on your PC screen.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            TextField(
              controller: _pinController,
              keyboardType: TextInputType.number,
              maxLength: 6,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 28,
                letterSpacing: 8,
                fontWeight: FontWeight.bold,
              ),
              decoration: const InputDecoration(
                hintText: '000000',
                border: OutlineInputBorder(),
                counterText: '',
              ),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _currentState == PairingState.sasEntered ? null : _submitPin,
              style: ElevatedButton.styleFrom(padding: const EdgeInsets.all(16)),
              child: _currentState == PairingState.sasEntered
                  ? const CircularProgressIndicator()
                  : const Text('Confirm PIN', style: TextStyle(fontSize: 18)),
            ),
            const SizedBox(height: 12),
            TextButton(
              onPressed: () => widget.pairingService.cancelPairing(),
              child: const Text('Cancel'),
            ),
          ],
        );

      case PairingState.pairingConfirmed:
      case PairingState.paired:
        return Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.check_circle, size: 80, color: Colors.green),
            const SizedBox(height: 16),
            Text(
              'Pairing Complete!',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text('Successfully paired with ${widget.targetPcHost}'),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Done'),
            ),
          ],
        );

      case PairingState.failed:
      case PairingState.expired:
      case PairingState.cancelled:
        return Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 80, color: Colors.red),
            const SizedBox(height: 16),
            Text(
              'Pairing Unsuccessful',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              _errorMessage.isNotEmpty ? _errorMessage : 'Operation was cancelled.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _startPairing,
              child: const Text('Try Again'),
            ),
          ],
        );

      default:
        return const SizedBox.shrink();
    }
  }
}
