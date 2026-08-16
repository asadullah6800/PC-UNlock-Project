import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_fingerprint_unlock/main.dart';

void main() {
  testWidgets('App smoke test - verifies HomeScreen title', (WidgetTester tester) async {
    await tester.pumpWidget(const MobileUnlockApp());

    expect(find.text('Mobile Fingerprint Unlock'), findsOneWidget);
    expect(find.text('Unlock PC'), findsOneWidget);
    expect(find.text('Lock PC'), findsOneWidget);
  });
}
