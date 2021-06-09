declare class AugSchemeMPL {
  static sk_to_g1(sk: PrivateKey): G1Element;
  static key_gen(msg: Uint8Array): PrivateKey;
  static sign(sk: PrivateKey, msg: Uint8Array): G2Element;
  static sign_prepend(sk: PrivateKey, msg: Uint8Array, prependPk: G1Element): G2Element;
  static verify(pk: G1Element, msg: Uint8Array, sig: G2Element): boolean;
  static aggregate(g2Elements: G2Element[]): G2Element;
  static aggregate_verify(pks: G1Element[], msgs: Uint8Array[], sig: G2Element): boolean;
  static derive_child_sk(sk: PrivateKey, index: number): PrivateKey;
  static derive_child_sk_unhardened(sk: PrivateKey, index: number): PrivateKey;
  static derive_child_pk_unhardened(pk: G1Element, index: number): G1Element;
}

declare class BasicSchemeMPL {
  static sk_to_g1(sk: PrivateKey): G1Element;
  static key_gen(msg: Uint8Array): PrivateKey;
  static sign(sk: PrivateKey, msg: Uint8Array): G2Element;
  static verify(pk: G1Element, msg: Uint8Array, sig: G2Element): boolean;
  static aggregate(g2Elements: G2Element[]): G2Element;
  static aggregate_verify(pks: G1Element[], msgs: Uint8Array[], sig: G2Element): boolean;
  static derive_child_sk(sk: PrivateKey, index: number): PrivateKey;
  static derive_child_sk_unhardened(sk: PrivateKey, index: number): PrivateKey;
  static derive_child_pk_unhardened(pk: G1Element, index: number): G1Element;
}

declare class PopSchemeMPL {
  static sk_to_g1(sk: PrivateKey): G1Element;
  static key_gen(msg: Uint8Array): PrivateKey;
  static sign(sk: PrivateKey, msg: Uint8Array): G2Element;
  static verify(pk: G1Element, msg: Uint8Array, sig: G2Element): boolean;
  static aggregate(g2Elements: G2Element[]): G2Element;
  static aggregate_verify(pks: G1Element[], msgs: Uint8Array[], sig: G2Element): boolean;
  static derive_child_sk(sk: PrivateKey, index: number): PrivateKey;
  static derive_child_sk_unhardened(sk: PrivateKey, index: number): PrivateKey;
  static derive_child_pk_unhardened(pk: G1Element, index: number): G1Element;
  static pop_prove(sk: PrivateKey): G2Element;
  static pop_verify(pk: G1Element, signatureProof: G2Element): boolean;
  static fast_aggregate_verify(pks: G1Element[], msg: Uint8Array, sig: G2Element): boolean;
}

declare class G1Element {
  static SIZE: number;
  fromBytes(msg: Uint8Array): G1Element;
  generator(): G2Element;
  serialize(): Uint8Array;
  negate(): G1Element;
  deepcopy(): G1Element;
  get_fingerprint(): number;
  add(): G1Element;
  mul(): G1Element;
}

declare class G2Element {
  static SIZE: number;
  fromBytes(): G2Element;
  generator(): G2Element;
  serialize(): Uint8Array;
  negate(): G2Element;
  deepcopy(): G2Element;
}

declare class PrivateKey {
    static PRIVATE_KEY_SIZE: number;
    static fromBytes(bytes: Uint8Array, modOrder: boolean): PrivateKey;
    static aggregate(pks: PrivateKey[]): PrivateKey;
    deepcopy(): PrivateKey;
    serialize(): Uint8Array;
    get_g1(): G1Element;
}

declare class Bignum {
  static fromString(s: string, radix: number): Bignum;
  toString(radix: number): string;
}

declare class Util {
  static hash256(msg: Uint8Array): Uint8Array;
}

interface ModuleInstance {
  AugSchemeMPL: typeof AugSchemeMPL;
  BasicSchemeMPL: typeof BasicSchemeMPL;
  PopSchemeMPL: typeof PopSchemeMPL;
  G1Element: typeof G1Element;
  G2Element: typeof G2Element;
  PrivateKey: typeof PrivateKey;
  Bignum: typeof Bignum;
  Util: typeof Util;
}

declare function createModule(options?: {}): Promise<ModuleInstance>;

export = createModule;
