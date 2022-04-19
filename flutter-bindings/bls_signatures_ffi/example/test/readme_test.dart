import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('test readme', () async {
    final seed = Uint8List.fromList(<int>[
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
    ]);

    final scheme = AugSchemeMPL();
    var sk = scheme.keyGen(seed);
    var pk = sk.g1Element();
    final msg = Uint8List.fromList(<int>[1, 2, 3, 4, 5]);
    var sig = scheme.sign(sk, msg);
    expect(scheme.verify(pk, msg, sig), true);

    final skRaw = sk.serialize();
    final pkRaw = pk.serialize();
    final sigRaw = sig.serialize();

    sk = PrivateKey.fromBytes(data: skRaw);
    pk = G1Element.fromBytes(data: pkRaw);
    sig = G2Element.fromBytes(data: sigRaw);

    final sk1 = scheme.keyGen(Uint8List.fromList(seed)..[0] = 1);
    final sk2 = scheme.keyGen(Uint8List.fromList(seed)..[0] = 2);
    final msg2 = Uint8List.fromList(<int>[1, 2, 3, 4, 5, 6, 7]);
    final pk1 = sk1.g1Element();
    final sig1 = scheme.sign(sk1, msg);
    final pk2 = sk2.g1Element();
    final sig2 = scheme.sign(sk2, msg2);
    final aggSig = scheme.aggregateSigs(<G2Element>[sig1, sig2]);
    expect(
      scheme.aggregateVerify(
        <G1Element>[pk1, pk2],
        <Uint8List>[msg, msg2],
        aggSig,
      ),
      true,
    );

    final sk3 = scheme.keyGen(Uint8List.fromList(seed)..[0] = 2);
    final pk3 = sk3.g1Element();
    final msg3 = Uint8List.fromList(<int>[100, 2, 254, 88, 90, 45, 23]);
    final sig3 = scheme.sign(sk3, msg3);
    final aggSigFinal = scheme.aggregateSigs(<G2Element>[aggSig, sig3]);
    expect(
      scheme.aggregateVerify(
        <G1Element>[pk1, pk2, pk3],
        <Uint8List>[msg, msg2, msg3],
        aggSigFinal,
      ),
      true,
    );

    final popScheme = PopSchemeMPL();
    final popSig1 = popScheme.sign(sk1, msg);
    final popSig2 = popScheme.sign(sk2, msg);
    final popSig3 = popScheme.sign(sk3, msg);
    final pop1 = popScheme.popProve(sk1);
    final pop2 = popScheme.popProve(sk2);
    final pop3 = popScheme.popProve(sk3);
    expect(popScheme.popVerify(pk1, pop1), true);
    expect(popScheme.popVerify(pk2, pop2), true);
    expect(popScheme.popVerify(pk3, pop3), true);

    final popSigAgg =
        popScheme.aggregateSigs(<G2Element>[popSig1, popSig2, popSig3]);
    expect(
      popScheme.fastAggregateVerify(<G1Element>[pk1, pk2, pk3], msg, popSigAgg),
      true,
    );

    final popAggPk = pk1 + pk2 + pk3;
    final tPopAggPk1 = pk1 + (pk2 + pk3);
    expect(popAggPk.serialize() == tPopAggPk1.serialize(), true);
    expect(popScheme.verify(popAggPk, msg, popSigAgg), true);

    final popAggSk = PrivateKey.aggregate(<PrivateKey>[sk1, sk2, sk3]);
    final popEqTest = popScheme.sign(popAggSk, msg);
    expect(popEqTest == popSigAgg, true);
    expect(popEqTest.serialize() == popSigAgg.serialize(), true);

    final masterSk = scheme.keyGen(seed);
    final masterPk = masterSk.g1Element();
    final childU = scheme.deriveChildSkUnhardened(masterSk, 22);
    final grandChildU = scheme.deriveChildSkUnhardened(childU, 0);
    final childUPk = scheme.deriveChildPkUnhardened(masterPk, 22);
    final grandChildUPk = scheme.deriveChildPkUnhardened(childUPk, 0);
    final grandChildUPkAlt = grandChildU.g1Element();
    expect(grandChildUPk.serialize() == grandChildUPkAlt.serialize(), true);

    scheme.free();
    sk.free();
    pk.free();
    sig.free();
    sk1.free();
    sk2.free();
    pk1.free();
    sig1.free();
    pk2.free();
    sig2.free();
    aggSig.free();
    sk3.free();
    pk3.free();
    sig3.free();
    aggSigFinal.free();
    popScheme.free();
    popSig1.free();
    popSig2.free();
    popSig3.free();
    pop1.free();
    pop2.free();
    pop3.free();
    popSigAgg.free();
    popAggPk.free();
    tPopAggPk1.free();
    popAggSk.free();
    popEqTest.free();
    masterSk.free();
    masterPk.free();
    childU.free();
    grandChildU.free();
    childUPk.free();
    grandChildUPk.free();
    grandChildUPkAlt.free();
  });
}
