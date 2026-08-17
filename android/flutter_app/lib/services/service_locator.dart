import 'connection_service.dart';
import '../security/biometric_security_service.dart';

class ServiceLocator {
  static final ServiceLocator _instance = ServiceLocator._internal();
  factory ServiceLocator() => _instance;
  ServiceLocator._internal();

  late final IConnectionService connectionService;
  late final BiometricSecurityService biometricSecurityService;

  void setup() {
    connectionService = MockConnectionService();
    biometricSecurityService = BiometricSecurityService();
  }
}

final locator = ServiceLocator();
