import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

import 'util.dart';

void main() {
  test('test aug scheme mpl', () async {
    final msg1 = Uint8List.fromList(<int>[1, 2, 3, 40]);
    final msg2 = Uint8List.fromList(<int>[5, 6, 70, 201]);
    final msg3 = Uint8List.fromList(<int>[9, 10, 11, 12, 13]);
    final msg4 = Uint8List.fromList(<int>[15, 63, 244, 92, 0, 1]);

    final scheme = AugSchemeMPL();
    final sk1 = scheme.keyGen(genSeed(value: 2));
    final sk2 = scheme.keyGen(genSeed(value: 3));
    final pk1 = sk1.g1Element();
    final pk2 = sk2.g1Element();

    final sig1 = scheme.sign(sk1, msg1);
    final sig2 = scheme.sign(sk2, msg2);
    final sig3 = scheme.sign(sk2, msg1);
    final sig4 = scheme.sign(sk1, msg3);
    final sig5 = scheme.sign(sk1, msg1);
    final sig6 = scheme.sign(sk1, msg4);

    final aggSigL = scheme.aggregateSigs(<G2Element>[sig1, sig2]);
    final aggSigR = scheme.aggregateSigs(<G2Element>[sig3, sig4, sig5]);
    final aggSig = scheme.aggregateSigs(<G2Element>[aggSigL, aggSigR, sig6]);

    final pks = <G1Element>[pk1, pk2, pk2, pk1, pk1, pk1];
    final msgs = <Uint8List>[msg1, msg2, msg1, msg3, msg1, msg4];
    expect(scheme.aggregateVerify(pks, msgs, aggSig), true);
    expect(
      aggSig.hexString() ==
          '''
0xa1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af44b6c4e9acd46eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847bbba0b2fd19ddc25ca964871997b9bceeab37a4c2565876da19382ea32a962200''',
      true,
    );

    scheme.free();
    sk1.free();
    sk2.free();
    pk1.free();
    pk2.free();
    sig1.free();
    sig2.free();
    sig3.free();
    sig4.free();
    sig5.free();
    sig6.free();
    aggSigL.free();
    aggSigR.free();
    aggSig.free();
  });
}
