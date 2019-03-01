/// <reference types="node" />

export class PrivateKey {
    static fromSeed(seed: Buffer): PrivateKey;
    static fromBytes(bytes: Buffer): PrivateKey;
    static aggregate(privateKeys: PrivateKey[]): PrivateKey;
    getPublicKey(): PublicKey;
    serialize(): Buffer;
    sign(message: Buffer): Signature;
    signPrehashed(messageHash: Buffer): Signature;
}

export class InsecureSignature {
    static fromBytes(bytes: Buffer);
    static aggregate(signatures: InsecureSignature[]): InsecureSignature;
    verify(hashes: Buffer[], pubKeys: PublicKey[]): boolean;
    divideBy(insecureSignatures: InsecureSignature[]): InsecureSignature;
    serialize(): Buffer;
}

export class Signature {
    static fromBytes(bytes: Buffer): Signature;
    static fromBytesAndAggregationInfo(bytes: Buffer, aggregationInfo: AggregationInfo): Signature;
    static aggregateSigs(signatures: Signature[]): Signature;
    serialize(): Buffer;
    verify(): boolean;
    getAggregationInfo(): AggregationInfo;
    setAggregationInfo(aggregationInfo: AggregationInfo): void;
}

export class PublicKey {
    static fromBytes(bytes: Buffer): PublicKey;
    static aggregate(publicKeys: PublicKey[]): PublicKey;
    getFingerprint(): number;
    serialize(): Buffer;
}

export class AggregationInfo {
    static fromMsgHash(publicKey: PublicKey, messageHash: Buffer): AggregationInfo;
    static fromMsg(publicKey: PublicKey, message: Buffer): AggregationInfo;
    static fromBuffers(pubKeys: PublicKey[], msgHashes: Buffer[], exponents: Buffer[]): AggregationInfo;
    getPublicKeys(): PublicKey[];
    getMessageHashes(): Buffer[];
    getExponents(): Buffer[];
}

export class ExtendedPrivateKey {
    static fromSeed(seed: Buffer): ExtendedPrivateKey;
    static fromBytes(bytes: Buffer): ExtendedPrivateKey;
    privateChild(index: number): ExtendedPrivateKey;
    publicChild(index: number): ExtendedPublicKey;
    getVersion(): number;
    getDepth(): number;
    getParentFingerprint(): number;
    getChildNumber(): number;
    getChainCode(): ChainCode;
    getPrivateKey(): PrivateKey;
    getPublicKey(): PublicKey;
    serialize(): Buffer;
}

export class ExtendedPublicKey {
    static fromBytes(bytes: Buffer): ExtendedPublicKey;
    publicChild(index: number): ExtendedPublicKey;
    getVersion(): number;
    getDepth(): number;
    getParentFingerprint(): number;
    getChildNumber(): number;
    getPublicKey(): PublicKey;
    serialize(): Buffer;
}

export class ChainCode {
    static fromBytes(bytes: Buffer);
    serialize(): Buffer;
}

export namespace Threshold {
    function create(commitment: PublicKey[], secretFragments: PrivateKey[], threshold: number, playersCount: number): PrivateKey;
    function signWithCoefficient(sk: PrivateKey, message: Buffer, playerIndex: number, players: number[]): InsecureSignature;
    function aggregateUnitSigs(sk: PrivateKey, message: Buffer, players: number[]) : InsecureSignature;
    function lagrangeCoeffsAtZero(players: number[]) : Buffer;
    function interpolateAtZero(X: Buffer, Y: Buffer, T: number): Buffer;
    function verifySecretFragment(playerIndex: number, secretFragment: PrivateKey, commitment: PublicKey[]) : boolean;
}
