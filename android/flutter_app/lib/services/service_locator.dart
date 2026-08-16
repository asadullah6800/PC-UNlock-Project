import 'connection_service.dart';

class ServiceLocator {
  static final ServiceLocator _instance = ServiceLocator._internal();
  factory ServiceLocator() => _instance;
  ServiceLocator._internal();

  late final IConnectionService connectionService;

  void setup() {
    connectionService = MockConnectionService();
  }
}

final locator = ServiceLocator();
