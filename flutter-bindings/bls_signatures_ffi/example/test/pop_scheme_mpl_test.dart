import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

import 'util.dart';

void main() {
  test('test pop scheme mpl', () async {
    final scheme = PopSchemeMPL();
    final sk1 = scheme.keyGen(genSeed(value: 4));
    final pop = scheme.popProve(sk1);
    final pk1 = sk1.g1Element();
    expect(scheme.popVerify(pk1, pop), true);
    expect(
      pop.hexString() ==
          '''
0x84f709159435f0dc73b3e8bf6c78d85282d19231555a8ee3b6e2573aaf66872d9203fefa1ef700e34e7c3f3fb28210100558c6871c53f1ef6055b9f06b0d1abe22ad584ad3b957f3018a8f58227c6c716b1e15791459850f2289168fa0cf9115''',
      true,
    );

    scheme.free();
    sk1.free();
    pop.free();
    pk1.free();
  });
}
