const loadBLS = require("../../js_build/js-bindings/blsjs.js");
let BLS;

beforeAll(async () => {
  BLS = await loadBLS();
});

test("test_schemes", () => {
  const seed = Uint8Array.from([
    0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6,
    220, 18, 102, 58, 209, 82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22
  ]);
  
  const msg = Uint8Array.from([100, 2, 254, 88, 90, 45, 23]);
  const msg2 = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const sk = BLS.BasicSchemeMPL.key_gen(seed);
  const pk = sk.get_g1();
  
  [BLS.BasicSchemeMPL, BLS.AugSchemeMPL, BLS.PopSchemeMPL].forEach(Scheme => {
    const sig = Scheme.sign(sk, msg);
    expect(Scheme.verify(pk, msg, sig)).toBeTruthy();
    sig.delete();
  });
  
  const seed1 = Uint8Array.of(1, ...seed.slice(1));
  const sk1 = BLS.BasicSchemeMPL.key_gen(seed1);
  const pk1 = sk1.get_g1();
  const seed2 = Uint8Array.of(2, ...seed.slice(1));
  const sk2 = BLS.BasicSchemeMPL.key_gen(seed2);
  const pk2 = sk2.get_g1();
  
  [BLS.BasicSchemeMPL, BLS.AugSchemeMPL, BLS.PopSchemeMPL].forEach(Scheme => {
    // Aggregate same message
    const agg_pk = pk1.add(pk2);
    let sig1, sig2;
    if (Scheme === BLS.AugSchemeMPL) {
      sig1 = Scheme.sign_prepend(sk1, msg, agg_pk);
      sig2 = Scheme.sign_prepend(sk2, msg, agg_pk);
    }
    else {
      sig1 = Scheme.sign(sk1, msg);
      sig2 = Scheme.sign(sk2, msg);
    }
    
    let agg_sig = Scheme.aggregate([sig1, sig2]);
    expect(Scheme.verify(agg_pk, msg, agg_sig)).toBeTruthy();
    sig1.delete();
    sig2.delete();
    agg_pk.delete();
    
    // Aggregate different message
    sig1 = Scheme.sign(sk1, msg)
    sig2 = Scheme.sign(sk2, msg2)
    agg_sig = Scheme.aggregate([sig1, sig2])
    expect(Scheme.aggregate_verify([pk1, pk2], [msg, msg2], agg_sig)).toBeTruthy();
    sig1.delete();
    sig2.delete();
    agg_sig.delete();
    
    // HD keys
    const child = Scheme.derive_child_sk(sk1, 123);
    const childU = Scheme.derive_child_sk_unhardened(sk1, 123);
    const childUPk = Scheme.derive_child_pk_unhardened(pk1, 123);
    
    const sig_child = Scheme.sign(child, msg);
    expect(Scheme.verify(child.get_g1(), msg, sig_child)).toBeTruthy();
    child.delete();
    sig_child.delete();
    
    const sigU_child = Scheme.sign(childU, msg);
    expect(Scheme.verify(childUPk, msg, sigU_child)).toBeTruthy();
    childU.delete();
    sigU_child.delete();
    childUPk.delete();
  });
  
  sk.delete();
  pk.delete();
  sk1.delete();
  pk1.delete();
  sk2.delete();
  pk2.delete();
});
