import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

import 'util.dart';

void main() {
  final testCases = <TestCase>[
    TestCase(
      index: 1,
      scheme: BasicSchemeMPL(),
      msgs: <Uint8List>[
        Uint8List.fromList(<int>[7, 8, 9]),
        Uint8List.fromList(<int>[10, 11, 12]),
        Uint8List.fromList(<int>[1, 2, 3]),
        Uint8List.fromList(<int>[1, 2, 3, 4]),
        Uint8List.fromList(<int>[1, 2]),
      ],
      refSig1: '''
0xb8faa6d6a3881c9fdbad803b170d70ca5cbf1e6ba5a586262df368c75acd1d1ffa3ab6ee21c71f844494659878f5eb230c958dd576b08b8564aad2ee0992e85a1e565f299cd53a285de729937f70dc176a1f01432129bb2b94d3d5031f8065a1''',
      refSk1:
          '0x4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604',
      refPk1: '''
0x85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911ef1e2e08749bddbf165352''',
      refSig2: '''
0xa9c4d3e689b82c7ec7e838dac2380cb014f9a08f6cd6ba044c263746e39a8f7a60ffee4afb78f146c2e421360784d58f0029491e3bd8ab84f0011d258471ba4e87059de295d9aba845c044ee83f6cf2411efd379ef38bf4cf41d5f3c0ae1205d''',
      refAggSig1: '''
0xaee003c8cdaf3531b6b0ca354031b0819f7586b5846796615aee8108fec75ef838d181f9d244a94d195d7b0231d4afcf06f27f0cc4d3c72162545c240de7d5034a7ef3a2a03c0159de982fbc2e7790aeb455e27beae91d64e077c70b5506dea3''',
      refAggSig2: '''
0xa0b1378d518bea4d1100adbc7bdbc4ff64f2c219ed6395cd36fe5d2aa44a4b8e710b607afd965e505a5ac3283291b75413d09478ab4b5cfbafbeea366de2d0c0bcf61deddaa521f6020460fd547ab37659ae207968b545727beba0a3c5572b9c''',
      pk1FingerPrint: 0xb40dd58a,
      pk2FingerPrint: 0xb839add1,
    ),
  ];

  tearDownAll(() {
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

  group('test basic scheme mpl', () {
    for (final tc in testCases) {
      test('case ${tc.index}', () async {
        final sk1 = tc.scheme.keyGen(genSeed(value: 0));
        final pk1 = sk1.g1Element();
        final sig1 = tc.scheme.sign(sk1, tc.msgs[0]);

        final sk2 = tc.scheme.keyGen(genSeed(value: 1));
        final pk2 = sk2.g1Element();
        final sig2 = tc.scheme.sign(sk2, tc.msgs[1]);

        expect(pk1.fingerprint() == 0xb40dd58a, true);
        expect(pk2.fingerprint() == 0xb839add1, true);

        expect(sig1.hexString() == tc.refSig1, true);
        expect(sig2.hexString() == tc.refSig2, true);
        expect(sk1.hexString() == tc.refSk1, true);
        expect(pk1.hexString() == tc.refPk1, true);

        final aggSig1 = tc.scheme.aggregateSigs(<G2Element>[sig1, sig2]);
        expect(aggSig1.hexString() == tc.refAggSig1, true);

        final pks = <G1Element>[pk1, pk2];
        expect(
          tc.scheme.aggregateVerify(
            pks,
            <Uint8List>[tc.msgs[0], tc.msgs[1]],
            aggSig1,
          ),
          true,
        );
        expect(
          tc.scheme.aggregateVerify(
            pks,
            <Uint8List>[tc.msgs[0], tc.msgs[1]],
            sig1,
          ),
          false,
        );
        expect(tc.scheme.verify(pk1, tc.msgs[0], sig2), false);
        expect(tc.scheme.verify(pk1, tc.msgs[1], sig1), false);

        final sig3 = tc.scheme.sign(sk1, tc.msgs[2]);
        final sig4 = tc.scheme.sign(sk1, tc.msgs[3]);
        final sig5 = tc.scheme.sign(sk2, tc.msgs[4]);
        final aggSig2 = tc.scheme.aggregateSigs(<G2Element>[sig3, sig4, sig5]);
        expect(aggSig2.hexString() == tc.refAggSig2, true);
        expect(
          tc.scheme.aggregateVerify(
            <G1Element>[pk1, pk1, pk2],
            tc.msgs.sublist(2),
            aggSig2,
          ),
          true,
        );
        expect(
          tc.scheme.aggregateVerify(
            <G1Element>[pk1, pk1, pk2],
            tc.msgs.sublist(2),
            aggSig1,
          ),
          false,
        );

        sk1.free();
        pk1.free();
        sig1.free();
        sk2.free();
        pk2.free();
        sig2.free();
        aggSig1.free();
        sig3.free();
        sig4.free();
        sig5.free();
        aggSig2.free();
      });
    }
  });

  test('test basic scheme mpl keygen', () async {
    final scheme = BasicSchemeMPL();
    final seed1 = genSeed(value: 8, length: 31);
    final seed2 = genSeed(value: 8);
    try {
      scheme.keyGen(seed1);
    } catch (e) {
      expect(e, const TypeMatcher<BLSException>());
    }
    final sk = scheme.keyGen(seed2);
    final pk = sk.g1Element();
    expect(pk.fingerprint(), 0x8ee7ba56);

    scheme.free();
    sk.free();
    pk.free();
  });
}

class TestCase {
  const TestCase({
    required this.index,
    required this.scheme,
    required this.msgs,
    required this.refSig1,
    required this.refSk1,
    required this.refPk1,
    required this.refSig2,
    required this.refAggSig1,
    required this.refAggSig2,
    required this.pk1FingerPrint,
    required this.pk2FingerPrint,
  });

  final int index;
  final CoreMPL scheme;
  final List<Uint8List> msgs;
  final String refSig1;
  final String refSk1;
  final String refPk1;
  final String refSig2;
  final String refAggSig1;
  final String refAggSig2;
  final int pk1FingerPrint;
  final int pk2FingerPrint;
}
