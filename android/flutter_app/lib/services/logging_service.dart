import 'package:flutter/foundation.dart';

enum LogLevel { info, warning, error }

class LoggingService {
  static void log(String message, {LogLevel level = LogLevel.info}) {
    if (kDebugMode) {
      final prefix = level.toString().split('.').last.toUpperCase();
      debugPrint('[$prefix] MobileUnlock: $message');
    }
  }

  static void info(String message) => log(message, level: LogLevel.info);
  static void warning(String message) => log(message, level: LogLevel.warning);
  static void error(String message) => log(message, level: LogLevel.error);
}
