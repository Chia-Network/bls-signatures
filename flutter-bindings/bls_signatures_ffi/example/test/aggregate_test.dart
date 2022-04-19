import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

import 'util.dart';

void main() {
  final schemes = <CoreMPL>[BasicSchemeMPL(), AugSchemeMPL(), PopSchemeMPL()];

  tearDownAll(() {
    (schemes[0] as BasicSchemeMPL).free();
    (schemes[1] as AugSchemeMPL).free();
    (schemes[2] as PopSchemeMPL).free();
  });

  group('test aggregate', () {
    final seed = <int>[
      0,
      50,
      6,
      244,
      24,
      199,
      1,
      25,
      52,
      88,
      192,
      19,
      18,
      12,
      89,
      6,
      220,
      18,
      102,
      58,
      209,
      82,
      12,
      62,
      89,
      110,
      182,
      9,
      44,
      20,
      254,
      22,
    ];
    final msg1 = Uint8List.fromList(<int>[100, 2, 254, 88, 90, 45, 23]);
    final msg2 = Uint8List.fromList(<int>[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    for (final scheme in schemes) {
      test(scheme.runtimeType, () async {
        final seed1 = Uint8List.fromList(seed)..[0] = 1;
        final seed2 = Uint8List.fromList(seed)..[0] = 1;
        final sk1 = scheme.keyGen(seed1);
        final pk1 = sk1.g1Element();
        final sk2 = scheme.keyGen(seed2);
        final pk2 = sk2.g1Element();
        final aggPk = pk1 + pk2;

        final sigs1 = <G2Element>[];
        if (scheme is AugSchemeMPL) {
          sigs1.addAll([
            scheme.signPrepend(sk1, msg1, aggPk),
            scheme.signPrepend(sk2, msg1, aggPk),
          ]);
        } else {
          sigs1.addAll([
            scheme.sign(sk1, msg1),
            scheme.sign(sk2, msg1),
          ]);
        }

        final aggSig1 = scheme.aggregateSigs(sigs1);
        expect(scheme.verify(aggPk, msg1, aggSig1), true);

        final sigs2 = <G2Element>[
          scheme.sign(sk1, msg1),
          scheme.sign(sk2, msg2),
        ];
        final aggSig2 = scheme.aggregateSigs(sigs2);
        expect(
          scheme.aggregateVerify(
            <G1Element>[pk1, pk2],
            <Uint8List>[msg1, msg2],
            aggSig2,
          ),
          true,
        );

        final child = scheme.deriveChildSk(sk1, 123);
        final childU = scheme.deriveChildSkUnhardened(sk1, 123);
        final childUPk = scheme.deriveChildPkUnhardened(pk1, 123);
        final sigChild = scheme.sign(child, msg1);
        final sigChildPk = child.g1Element();
        expect(scheme.verify(sigChildPk, msg1, sigChild), true);

        final sigUChild = scheme.sign(childU, msg1);
        expect(scheme.verify(childUPk, msg1, sigUChild), true);

        sk1.free();
        pk1.free();
        sk2.free();
        pk2.free();
        aggPk.free();
        for (final sig in sigs1) {
          sig.free();
        }
        aggSig1.free();
        for (final sig in sigs2) {
          sig.free();
        }
        aggSig2.free();
        child.free();
        childU.free();
        childUPk.free();
        sigChild.free();
        sigChildPk.free();
        sigUChild.free();
      });
    }
  });

  test('test aggregate secret keys', () async {
    final msg = Uint8List.fromList(<int>[100, 2, 254, 88, 90, 45, 23]);
    final scheme = BasicSchemeMPL();
    final sk1 = scheme.keyGen(genSeed(value: 7));
    final pk1 = sk1.g1Element();
    final sk2 = scheme.keyGen(genSeed(value: 8));
    final pk2 = sk2.g1Element();
    final aggSk = PrivateKey.aggregate(<PrivateKey>[sk1, sk2]);
    final aggSkAlt = PrivateKey.aggregate(<PrivateKey>[sk2, sk1]);
    expect(aggSk == aggSkAlt, true);

    final aggPubKey = pk1 + pk2;
    final aggPk = aggSk.g1Element();
    expect(aggPubKey == aggPk, true);

    final sig1 = scheme.sign(sk1, msg);
    final sig2 = scheme.sign(sk2, msg);
    final aggSig2 = scheme.sign(aggSk, msg);
    final aggSig = scheme.aggregateSigs(<G2Element>[sig1, sig2]);
    expect(aggSig == aggSig2, true);

    expect(scheme.verify(aggPubKey, msg, aggSig), true);
    expect(scheme.verify(aggPubKey, msg, aggSig2), true);

    expect(
      scheme.aggregateVerify(
        <G1Element>[pk1, pk2],
        <Uint8List>[msg, msg],
        aggSig,
      ),
      false,
    );
    expect(
      scheme.aggregateVerify(
        <G1Element>[pk1, pk2],
        <Uint8List>[msg, msg],
        aggSig2,
      ),
      false,
    );

    final msg2 = Uint8List.fromList(<int>[200, 29, 54, 8, 9, 29, 155, 55]);
    final sig3 = scheme.sign(sk2, msg2);
    final aggSigFinal = scheme.aggregateSigs(<G2Element>[aggSig, sig3]);
    final aggSigAlt = scheme.aggregateSigs(<G2Element>[sig1, sig2, sig3]);
    final aggSigAlt2 = scheme.aggregateSigs(<G2Element>[sig1, sig3, sig2]);
    expect(aggSigFinal == aggSigAlt, true);
    expect(aggSigFinal == aggSigAlt2, true);

    final skFinal = PrivateKey.aggregate(<PrivateKey>[aggSk, sk2]);
    final skFinalAlt = PrivateKey.aggregate(<PrivateKey>[sk2, sk1, sk2]);
    expect(skFinal == skFinalAlt, true);
    expect(skFinal != aggSk, true);

    final pkFinal = aggPubKey + pk2;
    final pkFinalAlt = pk2 + pk1 + pk2;
    expect(pkFinal == pkFinalAlt, true);
    expect(pkFinal != aggPubKey, true);

    expect(
      scheme.aggregateVerify(
        <G1Element>[aggPubKey, pk2],
        <Uint8List>[msg, msg2],
        aggSigFinal,
      ),
      true,
    );

    scheme.free();
    sk1.free();
    pk1.free();
    sk2.free();
    pk2.free();
    aggSk.free();
    aggSkAlt.free();
    aggPubKey.free();
    aggPk.free();
    sig1.free();
    sig2.free();
    aggSig2.free();
    aggSig.free();
    sig3.free();
    aggSigFinal.free();
    aggSigAlt.free();
    skFinal.free();
    skFinalAlt.free();
    pkFinal.free();
    pkFinalAlt.free();
  });
}
