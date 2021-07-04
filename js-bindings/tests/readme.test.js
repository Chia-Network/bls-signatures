const loadBLS = require("../../js_build/js-bindings/blsjs.js");

describe("Test code sample in README.md", () => {
  let BLS;
  const seed = Uint8Array.from([
    0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
    19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
    12, 62, 89, 110, 182, 9,   44, 20,  254, 22
  ]);
  
  // context of variables which can be accessed from tests in this block.
  const var_ = {
    sk: undefined,
    pk: undefined,
    message: undefined,
    signature: undefined,
    skBytes: undefined,
    pkBytes: undefined,
    signatureBytes: undefined,
    sk1: undefined,
    sk2: undefined,
    message2: undefined,
    pk1: undefined,
    sig1: undefined,
    pk2: undefined,
    sig2: undefined,
    aggSig: undefined,
    sk3: undefined,
    pk3: undefined,
    message3: undefined,
    sig3: undefined,
    aggSigFinal: undefined,
    popSig1: undefined,
    popSig2: undefined,
    popSig3: undefined,
    pop1: undefined,
    pop2: undefined,
    pop3: undefined,
    popSigAgg: undefined,
    popAggPk: undefined,
    aggSk: undefined,
    masterSk: undefined,
    child: undefined,
    grandChild: undefined,
    masterPk: undefined,
    childU: undefined,
    grandchildU: undefined,
    childUPk: undefined,
    grandchildUPk: undefined,
  };
  
  beforeAll(async () => {
    BLS = await loadBLS();
    
    /*
    Creating keys and signatures
     */
    var_.sk = BLS.AugSchemeMPL.key_gen(seed);
    var_.pk = var_.sk.get_g1();
  
    var_.message = Uint8Array.from([1,2,3,4,5]);
    var_.signature = BLS.AugSchemeMPL.sign(var_.sk, var_.message);
    
    /*
    Serializing keys and signatures to bytes
     */
    var_.skBytes = var_.sk.serialize();
    var_.pkBytes = var_.pk.serialize();
    var_.signatureBytes = var_.signature.serialize();
    
    /*
    Loading keys and signatures from bytes
     */
    // See test("Loading keys and signatures from bytes", () => ...);
    
    /*
    Create aggregate signatures
     */
    // Generate some more private keys
    seed[0] = 1;
    var_.sk1 = BLS.AugSchemeMPL.key_gen(seed);
    seed[0] = 2;
    var_.sk2 = BLS.AugSchemeMPL.key_gen(seed);
    var_.message2 = Uint8Array.from([1,2,3,4,5,6,7]);
  
    // Generate first sig
    var_.pk1 = var_.sk1.get_g1();
    var_.sig1 = BLS.AugSchemeMPL.sign(var_.sk1, var_.message);
  
    // Generate second sig
    var_.pk2 = var_.sk2.get_g1();
    var_.sig2 = BLS.AugSchemeMPL.sign(var_.sk2, var_.message2);
  
    // Signatures can be non-interactively combined by anyone
    var_.aggSig = BLS.AugSchemeMPL.aggregate([var_.sig1, var_.sig2]);
  
    /*
    Arbitrary trees of aggregates
     */
    seed[0] = 3;
    var_.sk3 = BLS.AugSchemeMPL.key_gen(seed);
    var_.pk3 = var_.sk3.get_g1();
    var_.message3 = Uint8Array.from([100, 2, 254, 88, 90, 45, 23]);
    var_.sig3 = BLS.AugSchemeMPL.sign(var_.sk3, var_.message3);
  
    var_.aggSigFinal = BLS.AugSchemeMPL.aggregate([var_.aggSig, var_.sig3]);
    
    /*
    Very fast verification with Proof of Possession scheme
     */
    // If the same message is signed, you can use Proof of Posession (PopScheme) for efficiency
    // A proof of possession MUST be passed around with the PK to ensure security.
    var_.popSig1 = BLS.PopSchemeMPL.sign(var_.sk1, var_.message);
    var_.popSig2 = BLS.PopSchemeMPL.sign(var_.sk2, var_.message);
    var_.popSig3 = BLS.PopSchemeMPL.sign(var_.sk3, var_.message);
    var_.pop1 = BLS.PopSchemeMPL.pop_prove(var_.sk1);
    var_.pop2 = BLS.PopSchemeMPL.pop_prove(var_.sk2);
    var_.pop3 = BLS.PopSchemeMPL.pop_prove(var_.sk3);
  
    var_.popSigAgg = BLS.PopSchemeMPL.aggregate([var_.popSig1, var_.popSig2, var_.popSig3]);
    
    // Aggregate public key, indistinguishable from a single public key
    var_.popAggPk = var_.pk1.add(var_.pk2).add(var_.pk3);
  
    // Aggregate private keys
    var_.aggSk = BLS.PrivateKey.aggregate([var_.sk1, var_.sk2, var_.sk3]);
    
    /*
    HD keys using EIP-2333
     */
    // You can derive 'child' keys from any key, to create arbitrary trees. 4 byte indeces are used.
    // Hardened (more secure, but no parent pk -> child pk)
    var_.masterSk = BLS.AugSchemeMPL.key_gen(seed);
    var_.child = BLS.AugSchemeMPL.derive_child_sk(var_.masterSk, 152);
    var_.grandChild = BLS.AugSchemeMPL.derive_child_sk(var_.child, 952);
  
    // Unhardened (less secure, but can go from parent pk -> child pk), BIP32 style
    var_.masterPk = var_.masterSk.get_g1();
    var_.childU = BLS.AugSchemeMPL.derive_child_sk_unhardened(var_.masterSk, 22);
    var_.grandchildU = BLS.AugSchemeMPL.derive_child_sk_unhardened(var_.childU, 0);
  
    var_.childUPk = BLS.AugSchemeMPL.derive_child_pk_unhardened(var_.masterPk, 22);
    var_.grandchildUPk = BLS.AugSchemeMPL.derive_child_pk_unhardened(var_.childUPk, 0);
  });
  
  test("Creating keys and signatures", () => {
    expect(BLS.AugSchemeMPL.verify(var_.pk, var_.message, var_.signature)).toBeTruthy();
  });
  
  test("Serializing keys and signatures to bytes", () => {
    expect(BLS.Util.hex_str(var_.skBytes)).toBe("377091f0e728463bc2da7d546c53b9f6b81df4a1cc1ab5bf29c5908b7151a32d");
    expect(BLS.Util.hex_str(var_.pkBytes)).toBe("86243290bbcbfd9ae75bdece7981965350208eb5e99b04d5cd24e955ada961f8c0a162dee740be7bdc6c3c0613ba2eb1");
    expect(BLS.Util.hex_str(var_.signatureBytes)).toBe("b00ab9a8af54804b43067531d96c176710c05980fccf8eee1ae12a4fd543df929cce860273af931fe4fdbc407d495f73114ab7d17ef08922e56625daada0497582340ecde841a9e997f2f557653c21c070119662dd2efa47e2d6c5e2de00eefa");
  });
  
  test("Loading keys and signatures from bytes", () => {
    expect(() => BLS.PrivateKey.from_bytes(var_.skBytes, false)).not.toThrow();
    expect(BLS.PrivateKey.from_bytes(var_.skBytes, false).serialize()).toEqual(var_.skBytes);
    
    expect(() => BLS.G1Element.from_bytes(var_.pkBytes)).not.toThrow();
    expect(BLS.G1Element.from_bytes(var_.pkBytes).serialize()).toEqual(var_.pkBytes);
  });
  
  test("Create aggregate signatures", () => {
    expect(BLS.AugSchemeMPL.aggregate_verify([var_.pk1, var_.pk2], [var_.message, var_.message2], var_.aggSig)).toBeTruthy();
  });
  
  test("Arbitrary trees of aggregates", () => {
    expect(BLS.AugSchemeMPL.aggregate_verify([var_.pk1, var_.pk2, var_.pk3], [var_.message, var_.message2, var_.message3], var_.aggSigFinal)).toBeTruthy();
  });
  
  test("Very fast verification with Proof of Possession scheme", () => {
    expect(BLS.PopSchemeMPL.pop_verify(var_.pk1, var_.pop1)).toBeTruthy();
    expect(BLS.PopSchemeMPL.pop_verify(var_.pk2, var_.pop2)).toBeTruthy();
    expect(BLS.PopSchemeMPL.pop_verify(var_.pk3, var_.pop3)).toBeTruthy();
    expect(BLS.PopSchemeMPL.fast_aggregate_verify([var_.pk1, var_.pk2, var_.pk3], var_.message, var_.popSigAgg)).toBeTruthy();
    expect(BLS.PopSchemeMPL.verify(var_.popAggPk, var_.message, var_.popSigAgg)).toBeTruthy();
    expect(BLS.PopSchemeMPL.sign(var_.aggSk, var_.message).equal_to(var_.popSigAgg)).toBeTruthy();
  });
  
  test("HD keys using EIP-2333", () => {
    expect(var_.grandchildUPk.equal_to(var_.grandchildU.get_g1())).toBeTruthy();
  });
  
  afterAll(() => {
    // sk.delete();
    // pk.delete();
    // sig1.delete();
    // ...
    Object.values(var_).forEach(blsVariable => {
      if(blsVariable && typeof blsVariable.delete === "function"){
        blsVariable.delete();
      }
    });
  });
});
