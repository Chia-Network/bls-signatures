import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final secret1 = <int>[];
  final secret2 = <int>[];
  for (var i = 0; i < 32; i++) {
    secret1.add(1);
    secret2.add(i * 314159 % 256);
  }
  final sk1 = PrivateKey.fromBytes(data: Uint8List.fromList(secret1));
  final sk2 = PrivateKey.fromBytes(data: Uint8List.fromList(secret2));
  final msg = Uint8List.fromList(<int>[3, 1, 4, 1, 5, 9]);

  final testCases = <TestCase>[
    TestCase(
      name: 'testing of signature serialization of the basic scheme',
      scheme: BasicSchemeMPL(),
      refSig1: '''
0x96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99''',
      refSig2: '''
0xa402790932130f766af11ba716536683d8c4cfa51947e4f9081fedd692d6dc0cac5b904bee5ea6e25569e36d7be4ca59069a96e34b7f700758b716f9494aaa59a96e74d14a3b552a9a6bc129e717195b9d6006fd6d5cef4768c022e0f7316abf''',
      refSigA: '''
0x987cfd3bcd62280287027483f29c55245ed831f51dd6bd999a6ff1a1f1f1f0b647778b0167359c71505558a76e158e66181ee5125905a642246b01e7fa5ee53d68a4fe9bfb29a8e26601f0b9ad577ddd18876a73317c216ea61f430414ec51c5''',
    ),
    TestCase(
      name: 'testing of signature serialization of the augmented scheme',
      scheme: AugSchemeMPL(),
      refSig1: '''
0x8180f02ccb72e922b152fcedbe0e1d195210354f70703658e8e08cbebf11d4970eab6ac3ccf715f3fb876df9a9797abd0c1af61aaeadc92c2cfe5c0a56c146cc8c3f7151a073cf5f16df38246724c4aed73ff30ef5daa6aacaed1a26ecaa336b''',
      refSig2: '''
0x99111eeafb412da61e4c37d3e806c6fd6ac9f3870e54da9222ba4e494822c5b7656731fa7a645934d04b559e9261b86201bbee57055250a459a2da10e51f9c1a6941297ffc5d970a557236d0bdeb7cf8ff18800b08633871a0f0a7ea42f47480''',
      refSigA: '''
0x8c5d03f9dae77e19a5945a06a214836edb8e03b851525d84b9de6440e68fc0ca7303eeed390d863c9b55a8cf6d59140a01b58847881eb5af67734d44b2555646c6616c39ab88d253299acc1eb1b19ddb9bfcbe76e28addf671d116c052bb1847''',
    ),
    TestCase(
      name: '''
testing of signature serialization of the proof of possession scheme''',
      scheme: PopSchemeMPL(),
      refSig1: '''
0x9550fb4e7f7e8cc4a90be8560ab5a798b0b23000b6a54a2117520210f986f3f281b376f259c0b78062d1eb3192b3d9bb049f59ecc1b03a7049eb665e0df36494ae4cb5f1136ccaeefc9958cb30c3333d3d43f07148c386299a7b1bfc0dc5cf7c''',
      refSig2: '''
0xa69036bc11ae5efcbf6180afe39addde7e27731ec40257bfdc3c37f17b8df68306a34ebd10e9e32a35253750df5c87c2142f8207e8d5654712b4e554f585fb6846ff3804e429a9f8a1b4c56b75d0869ed67580d789870babe2c7c8a9d51e7b2a''',
      refSigA: '''
0xa4ea742bcdc1553e9ca4e560be7e5e6c6efa6a64dddf9ca3bb2854233d85a6aac1b76ec7d103db4e33148b82af9923db05934a6ece9a7101cd8a9d47ce27978056b0f5900021818c45698afdd6cf8a6b6f7fee1f0b43716f55e413d4b87a6039''',
    ),
  ];

  tearDownAll(() {
    sk1.free();
    sk2.free();
    for (final tc in testCases) {
      final scheme = tc.scheme;
      if (scheme is BasicSchemeMPL) {
        scheme.free();
      } else if (scheme is AugSchemeMPL) {
        scheme.free();
      } else if (scheme is PopSchemeMPL) {
        scheme.free();
      }
    }
  });

  group('test vector valid', () {
    for (final tc in testCases) {
      test(tc.name, () async {
        final sig1 = tc.scheme.sign(sk1, msg);
        final sig2 = tc.scheme.sign(sk2, msg);
        final sigA = tc.scheme.aggregateSigs(<G2Element>[sig1, sig2]);
        expect(sig1.hexString() == tc.refSig1, true);
        expect(sig2.hexString() == tc.refSig2, true);
        expect(sigA.hexString() == tc.refSigA, true);

        sig1.free();
        sig2.free();
        sigA.free();
      });
    }
  });
}

class TestCase {
  const TestCase({
    required this.name,
    required this.scheme,
    required this.refSig1,
    required this.refSig2,
    required this.refSigA,
  });

  final String name;
  final CoreMPL scheme;
  final String refSig1;
  final String refSig2;
  final String refSigA;
}
