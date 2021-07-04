const loadBLS = require("../../js_build/js-bindings/blsjs.js");
const {Hex} = require("jscrypto");

let BLS;

beforeAll(async () => {
  BLS = await loadBLS();
});

test("test_vectors_invalid", () => {
  // Invalid inputs from https://github.com/algorand/bls_sigs_ref/blob/master/python-impl/serdesZ.py
  const invalid_inputs_1 = [
    // infinity points: too short
    "c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    // infinity points: not all zeros
    "c00000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000",
    // bad tags
    "3a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
    "7a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
    "fa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
    // wrong length for compresed point
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa",
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaaaa",
    // invalid x-coord
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
    // invalid elm of Fp --- equal to p (must be strictly less)
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
  ]
  const invalid_inputs_2 = [
    // infinity points: too short
    "c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    // infinity points: not all zeros
    "c00000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000",
    // bad tags
    "3a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "7a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "fa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    // wrong length for compressed point
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    // invalid x-coord
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa7",
    // invalid elm of Fp --- equal to p (must be strictly less)
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
  ];
  
  invalid_inputs_1.forEach((s) => {
    const bytes_ = Hex.parse(s).toUint8Array();
    expect(() => BLS.G1Element(bytes_)).toThrow();
  });
  
  invalid_inputs_2.forEach((s) => {
    const bytes_ = Hex.parse(s).toUint8Array();
    expect(() => BLS.G2Element(bytes_)).toThrow();
  });
});

test("test_vectors_valid", () => {
  // The following code was used to generate these vectors
  //
  //   from py_ecc.bls import (
  //        G2Basic,
  //        G2MessageAugmentation as G2MA,
  //        G2ProofOfPossession as G2Pop,
  //    )
  //
  //    secret1 = bytes([1] * 32)
  //    secret2 = bytes([x * 314159 % 256 for x in range(32)])
  //    sk1 = int.from_bytes(secret1, 'big')
  //    sk2 = int.from_bytes(secret2, 'big')
  //    msg = bytes([3, 1, 4, 1, 5, 9])
  //    pk1 = G2Basic.SkToPk(sk1)
  //    pk2 = G2Basic.SkToPk(sk2)
  //
  //    for Scheme in (G2Basic, G2MA, G2Pop):
  //        sig1 = Scheme.Sign(sk1, msg)
  //        sig2 = Scheme.Sign(sk2, msg)
  //        sig_agg = Scheme.Aggregate([sig1, sig2])
  //        print(sig1)
  //        print(sig2)
  //        print(sig_agg)
  //
  // Javascript version converts these strings to binascii
  
  const bytes = (x) => {
    return Hex.parse(x).toUint8Array();
  };
  
  const range = (n) => {
    const arr = [];
    for(let i=0;i<n;i++){
      arr.push(i);
    }
    return arr;
  };
  
  const repeat = (n, v) => {
    return range(n).map(() => v);
  };
  
  const ref_sig1Basic = bytes('96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99');
  const ref_sig2Basic = bytes('a402790932130f766af11ba716536683d8c4cfa51947e4f9081fedd692d6dc0cac5b904bee5ea6e25569e36d7be4ca59069a96e34b7f700758b716f9494aaa59a96e74d14a3b552a9a6bc129e717195b9d6006fd6d5cef4768c022e0f7316abf');
  const ref_sigABasic = bytes('987cfd3bcd62280287027483f29c55245ed831f51dd6bd999a6ff1a1f1f1f0b647778b0167359c71505558a76e158e66181ee5125905a642246b01e7fa5ee53d68a4fe9bfb29a8e26601f0b9ad577ddd18876a73317c216ea61f430414ec51c5');
  const ref_sig1Aug = bytes('8180f02ccb72e922b152fcedbe0e1d195210354f70703658e8e08cbebf11d4970eab6ac3ccf715f3fb876df9a9797abd0c1af61aaeadc92c2cfe5c0a56c146cc8c3f7151a073cf5f16df38246724c4aed73ff30ef5daa6aacaed1a26ecaa336b');
  const ref_sig2Aug = bytes('99111eeafb412da61e4c37d3e806c6fd6ac9f3870e54da9222ba4e494822c5b7656731fa7a645934d04b559e9261b86201bbee57055250a459a2da10e51f9c1a6941297ffc5d970a557236d0bdeb7cf8ff18800b08633871a0f0a7ea42f47480');
  const ref_sigAAug = bytes('8c5d03f9dae77e19a5945a06a214836edb8e03b851525d84b9de6440e68fc0ca7303eeed390d863c9b55a8cf6d59140a01b58847881eb5af67734d44b2555646c6616c39ab88d253299acc1eb1b19ddb9bfcbe76e28addf671d116c052bb1847');
  const ref_sig1Pop = bytes('9550fb4e7f7e8cc4a90be8560ab5a798b0b23000b6a54a2117520210f986f3f281b376f259c0b78062d1eb3192b3d9bb049f59ecc1b03a7049eb665e0df36494ae4cb5f1136ccaeefc9958cb30c3333d3d43f07148c386299a7b1bfc0dc5cf7c');
  const ref_sig2Pop = bytes('a69036bc11ae5efcbf6180afe39addde7e27731ec40257bfdc3c37f17b8df68306a34ebd10e9e32a35253750df5c87c2142f8207e8d5654712b4e554f585fb6846ff3804e429a9f8a1b4c56b75d0869ed67580d789870babe2c7c8a9d51e7b2a');
  const ref_sigAPop = bytes('a4ea742bcdc1553e9ca4e560be7e5e6c6efa6a64dddf9ca3bb2854233d85a6aac1b76ec7d103db4e33148b82af9923db05934a6ece9a7101cd8a9d47ce27978056b0f5900021818c45698afdd6cf8a6b6f7fee1f0b43716f55e413d4b87a6039');
  
  const secret1 = Uint8Array.from(repeat(32, 1));
  const secret2 = Uint8Array.from(range(32).map((x) => x * 314159 % 256));
  const sk1 = BLS.PrivateKey.from_bytes(secret1, false);
  const sk2 = BLS.PrivateKey.from_bytes(secret2, false);
  
  const msg = Uint8Array.from([3, 1, 4, 1, 5, 9]);
  const sig1Basic = BLS.BasicSchemeMPL.sign(sk1, msg)
  const sig2Basic = BLS.BasicSchemeMPL.sign(sk2, msg)
  const sigABasic = BLS.BasicSchemeMPL.aggregate([sig1Basic, sig2Basic])
  const sig1Aug = BLS.AugSchemeMPL.sign(sk1, msg)
  const sig2Aug = BLS.AugSchemeMPL.sign(sk2, msg)
  const sigAAug = BLS.AugSchemeMPL.aggregate([sig1Aug, sig2Aug])
  const sig1Pop = BLS.PopSchemeMPL.sign(sk1, msg)
  const sig2Pop = BLS.PopSchemeMPL.sign(sk2, msg)
  const sigAPop = BLS.PopSchemeMPL.aggregate([sig1Pop, sig2Pop])
  
  expect(Uint8Array.from(sig1Basic.serialize())).toEqual(ref_sig1Basic);
  expect(Uint8Array.from(sig2Basic.serialize())).toEqual(ref_sig2Basic);
  expect(Uint8Array.from(sigABasic.serialize())).toEqual(ref_sigABasic);
  expect(Uint8Array.from(sig1Aug.serialize())).toEqual(ref_sig1Aug);
  expect(Uint8Array.from(sig2Aug.serialize())).toEqual(ref_sig2Aug);
  expect(Uint8Array.from(sigAAug.serialize())).toEqual(ref_sigAAug);
  expect(Uint8Array.from(sig1Pop.serialize())).toEqual(ref_sig1Pop);
  expect(Uint8Array.from(sig2Pop.serialize())).toEqual(ref_sig2Pop);
  expect(Uint8Array.from(sigAPop.serialize())).toEqual(ref_sigAPop);
});
