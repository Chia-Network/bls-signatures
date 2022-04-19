import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';

void main() {
  const MethodChannel channel = MethodChannel('bls_signatures_ffi');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await BlsSignaturesFfi.platformVersion, '42');
  });
}
