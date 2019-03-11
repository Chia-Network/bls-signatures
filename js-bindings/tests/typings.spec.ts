// This file is used to check if the typescript typings are working
import {
    PrivateKey,
    PublicKey,
    ExtendedPrivateKey,
    ChainCode,
    AggregationInfo,
    Signature,
    Threshold,
    InsecureSignature,
    ExtendedPublicKey
} from '../';
import { strict as assert } from 'assert';

describe('PrivateKey', () => {
    const sk: PrivateKey = PrivateKey.fromSeed(Uint8Array.from([1,2,3]));
    const sk2: PrivateKey = PrivateKey.fromBytes(Uint8Array.from([1,2,3]), false);
    const aggSk: PrivateKey = PrivateKey.aggregate([], []);
    const aggSk2: PrivateKey = PrivateKey.aggregateInsecure([]);
    const pk: PublicKey = sk.getPublicKey();
    const bytes: Uint8Array = sk.serialize();
    const sig: Signature = sk.sign(Uint8Array.from([1,2,3]));
    const insecureSig: InsecureSignature = sk.signInsecure(Uint8Array.from([1,2,3]));
    const prehashedSig: Signature = sk.signPrehashed(Uint8Array.from([1,2,3]));
    sk.delete();
});

describe('InsecureSignature', () => {
    const sig: InsecureSignature = InsecureSignature.fromBytes(Uint8Array.from([1,2,3]));
    const aggSig: InsecureSignature = InsecureSignature.aggregate([]);
    const isValid: boolean = sig.verify([], []);
    const serialized: Uint8Array = sig.serialize();
    sig.delete();
});

describe('Signature', () => {
    const info = AggregationInfo.fromMsg(PublicKey.fromBytes(Uint8Array.from([1,2,3])), Uint8Array.from([1,2,3]));
    const sig: Signature = Signature.fromBytes(Uint8Array.from([1,2,3]));
    const aggSig: Signature = Signature.aggregateSigs([]);
    const sig2: Signature = Signature.fromBytesAndAggregationInfo(Uint8Array.from([1,2,3]), info);
    const isValid: boolean = sig.verify();
    const serialized: Uint8Array= sig.serialize();
    const aggInfo: AggregationInfo = sig.getAggregationInfo();
    sig.setAggregationInfo(info);
    sig.delete();
});

describe('PublicKey', () => {
    const pk: PublicKey = PublicKey.fromBytes(Uint8Array.from([1,2,3]));
    const aggPk: PublicKey = PublicKey.aggregate([]);
    const aggPk2: PublicKey = PublicKey.aggregateInsecure([]);
    const fingerprint: number = pk.getFingerprint();
    const bytes: Uint8Array = pk.serialize();
    pk.delete();
});

describe('AggregationInfo', () => {
    const infoFromHash: AggregationInfo = AggregationInfo.fromMsgHash(PublicKey.fromBytes(Uint8Array.from([1,2,3])), Uint8Array.from([1,2,3]));
    const info: AggregationInfo = AggregationInfo.fromMsg(PublicKey.fromBytes(Uint8Array.from([1,2,3])), Uint8Array.from([1,2,3]));
    const infroFromBuffers: AggregationInfo = AggregationInfo.fromBuffers([], [], []);
    const pks: PublicKey[] = info.getPublicKeys();
    const messageHashes: Uint8Array[] = info.getMessageHashes();
    const exponents: Uint8Array[] = info.getExponents();
    info.delete();
});

describe('ExtendedPrivateKey', () => {
    const esk: ExtendedPrivateKey = ExtendedPrivateKey.fromSeed(Uint8Array.from([1,2,3]));
    ExtendedPrivateKey.fromBytes(Uint8Array.from([1,2,3]));
    const privateChild: ExtendedPrivateKey = esk.privateChild(1);
    const publicChild: ExtendedPublicKey = esk.publicChild(1);
    const version: number = esk.getVersion();
    const depth: number = esk.getDepth();
    const parentFingerprint: number = esk.getParentFingerprint();
    const childNumber: number = esk.getChildNumber();
    const chainCode: ChainCode = esk.getChainCode();
    const sk: PrivateKey = esk.getPrivateKey();
    const pk: PublicKey = esk.getPublicKey();
    const epk: ExtendedPublicKey = esk.getExtendedPublicKey();
    const bytes: Uint8Array = esk.serialize();
    esk.delete();
});

describe('ExtendedPublicKey', () => {
    const epk: ExtendedPublicKey = ExtendedPublicKey.fromBytes(Uint8Array.from([1,2,3]));
    const publicChild: ExtendedPublicKey = epk.publicChild(1);
    const version: number = epk.getVersion();
    const depth: number = epk.getDepth();
    const parentFingerprint: number = epk.getParentFingerprint();
    const childNumber: number = epk.getChildNumber();
    const pk: PublicKey = epk.getPublicKey();
    const chainCode: ChainCode = epk.getChainCode();
    const bytes: Uint8Array = epk.serialize();
    epk.delete();
});

describe('ChainCode', () => {
    const chainCode: ChainCode = ChainCode.fromBytes(Uint8Array.from([1,2,3]));
    const bytes: Uint8Array = chainCode.serialize();
    chainCode.delete();
});

describe('Threshold', () => {
    const sk: PrivateKey = Threshold.create([], [], 2, 3);
    const sig: InsecureSignature = Threshold.signWithCoefficient(sk, Uint8Array.from([1,2,3]), 2, [1,3]);
    const aggSig: InsecureSignature = Threshold.aggregateUnitSigs([], Uint8Array.from([1,2,3]), [1, 2]);
    const isValid: boolean = Threshold.verifySecretFragment(1, sk, [], 3);
});