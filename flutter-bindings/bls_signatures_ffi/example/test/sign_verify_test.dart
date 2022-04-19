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

  group('test sign and verification', () {
    final msg = Uint8List.fromList(<int>[100, 2, 254, 88, 90, 45, 23]);
    for (final scheme in schemes) {
      test(scheme.runtimeType, () async {
        final sk = scheme.keyGen(genSeed(value: 1));
        final pk = sk.g1Element();
        final sig = scheme.sign(sk, msg);
        expect(scheme.verify(pk, msg, sig), true);

        sk.free();
        pk.free();
        sig.free();
      });
    }
  });
}
