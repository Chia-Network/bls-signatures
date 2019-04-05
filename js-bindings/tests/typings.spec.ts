// This file is used to check if the typescript typings are working
import {
    AggregationInfo,
    ChainCode,
    ExtendedPrivateKey,
    ExtendedPublicKey,
    GROUP_ORDER,
    InsecureSignature,
    PrivateKey,
    PublicKey,
    Signature,
    Threshold,
    DHKeyExchange
} from '../';
import {deepStrictEqual, ok, strictEqual} from 'assert';
import {createHash} from 'crypto';

function getSkSeed(): Uint8Array {
    return Uint8Array.from([1, 2, 3]);
}

function getSkBytes(): Uint8Array {
    return Uint8Array.from([17, 124, 119, 158, 68, 227, 109, 63, 132, 68, 94, 198, 126, 236, 73, 71, 11, 7, 137, 235, 99, 63, 16, 34, 9, 175, 110, 14, 189, 156, 27, 249]);
}

function getPkBytes(): Uint8Array {
    return Uint8Array.from([15, 128, 94, 226, 6, 236, 252, 3, 126, 41, 152, 204, 169, 80, 66, 245, 222, 64, 241, 191, 28, 142, 160, 62, 49, 244, 132, 97, 169, 171, 155, 96, 74, 253, 238, 108, 207, 75, 69, 38, 180, 24, 158, 26, 205, 241, 96, 236]);
}

function getMessageBytes(): Uint8Array {
    return Uint8Array.from([1, 2, 3]);
}

function getMessageHash(): Uint8Array {
    return Uint8Array.from(createHash('sha256').update(getMessageBytes()).digest());
}

function getSignatureBytes(): Uint8Array {
    return Uint8Array.from([131, 187, 59, 142, 42, 69, 254, 152, 172, 85, 1, 103, 4, 107, 65, 193, 195, 175, 119, 132, 122, 179, 123, 253, 215, 68, 17, 175, 180, 243, 5, 84, 167, 202, 236, 130, 219, 226, 72, 63, 235, 94, 225, 180, 148, 103, 109, 90, 24, 188, 105, 125, 165, 74, 188, 127, 250, 160, 207, 30, 196, 106, 168, 62, 79, 168, 219, 76, 43, 87, 167, 252, 69, 187, 113, 173, 182, 0, 137, 145, 4, 131, 190, 251, 181, 23, 82, 188, 87, 127, 242, 46, 234, 237, 220, 9]);
}

function getEskBytes(): Uint8Array {
    return Uint8Array.from([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 75, 79, 148, 193, 235, 158, 172, 163, 41, 102, 134, 72, 161, 187, 104, 97, 202, 38, 27, 206, 125, 64, 60, 149, 248, 29, 53, 180, 23, 253, 255, 81, 166, 177, 172, 207, 58, 74, 10, 229, 43, 174, 77, 91, 222, 159, 24, 29, 11, 190, 149, 27, 94, 76, 12, 100, 94, 17, 220, 38, 66, 179, 28]);
}

function getEpkBytes(): Uint8Array {
    return Uint8Array.from([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 75, 79, 148, 193, 235, 158, 172, 163, 41, 102, 134, 72, 161, 187, 104, 97, 202, 38, 27, 206, 125, 64, 60, 149, 248, 29, 53, 180, 23, 253, 255, 24, 98, 251, 112, 141, 167, 192, 161, 112, 151, 212, 18, 81, 160, 252, 201, 123, 120, 210, 54, 179, 74, 108, 219, 124, 123, 134, 186, 135, 75, 153, 183, 255, 54, 167, 17, 156, 63, 152, 194, 167, 30, 154, 29, 70, 218, 114, 53]);
}

function getChainCodeBytes(): Uint8Array {
    return Uint8Array.from([137, 75, 79, 148, 193, 235, 158, 172, 163, 41, 102, 134, 72, 161, 187, 104, 97, 202, 38, 27, 206, 125, 64, 60, 149, 248, 29, 53, 180, 23, 253, 255]);
}

describe('typings', () => {
    it('PrivateKey', () => {
        strictEqual(PrivateKey.PRIVATE_KEY_SIZE, 32);
        const sk: PrivateKey = PrivateKey.fromSeed(getSkSeed());
        const sk2: PrivateKey = PrivateKey.fromBytes(getSkBytes(), false);
        const aggSk: PrivateKey = PrivateKey.aggregate([sk], [sk.getPublicKey()]);
        const aggSk2: PrivateKey = PrivateKey.aggregateInsecure([sk]);
        const pk: PublicKey = sk.getPublicKey();
        const bytes: Uint8Array = sk.serialize();
        const sig: Signature = sk.sign(getMessageBytes());
        const insecureSig: InsecureSignature = sk.signInsecure(getMessageBytes());
        const prehashedSig: Signature = sk.signPrehashed(getMessageHash());
        ok(sig.verify());
        sk.delete();
        sk2.delete();
        aggSk.delete();
        aggSk2.delete();
        pk.delete();
        sig.delete();
        insecureSig.delete();
        prehashedSig.delete();
    });

    it('InsecureSignature', () => {
        strictEqual(InsecureSignature.SIGNATURE_SIZE, 96);
        const sig: InsecureSignature = InsecureSignature.fromBytes(getSignatureBytes());
        const aggSig: InsecureSignature = InsecureSignature.aggregate([sig]);
        const isValid: boolean = sig.verify([getMessageHash()], [PublicKey.fromBytes(getPkBytes())]);
        const serialized: Uint8Array = sig.serialize();
        ok(isValid);
        sig.delete();
        aggSig.delete();
    });

    it('Signature', () => {
        strictEqual(Signature.SIGNATURE_SIZE, 96);
        const info = AggregationInfo.fromMsg(PublicKey.fromBytes(getPkBytes()), getMessageBytes());
        const sig: Signature = Signature.fromBytesAndAggregationInfo(getSignatureBytes(), info);
        const aggSig: Signature = Signature.aggregateSigs([sig]);
        const sig2: Signature = Signature.fromBytes(getSignatureBytes());
        const isValid: boolean = sig.verify();
        const serialized: Uint8Array = sig.serialize();
        const aggInfo: AggregationInfo = sig.getAggregationInfo();
        ok(isValid);
        sig.setAggregationInfo(info);
        sig.delete();
        aggSig.delete();
        sig2.delete();
        aggInfo.delete();
    });

    it('PublicKey', () => {
        strictEqual(PublicKey.PUBLIC_KEY_SIZE, 48);
        const pk: PublicKey = PublicKey.fromBytes(getPkBytes());
        const aggPk: PublicKey = PublicKey.aggregate([pk]);
        const aggPk2: PublicKey = PublicKey.aggregateInsecure([pk]);
        const fingerprint: number = pk.getFingerprint();
        const bytes: Uint8Array = pk.serialize();
        pk.delete();
        aggPk.delete();
        aggPk2.delete();
    });

    it('AggregationInfo', () => {
        const infoFromHash: AggregationInfo = AggregationInfo.fromMsgHash(PublicKey.fromBytes(getPkBytes()), getMessageHash());
        const info: AggregationInfo = AggregationInfo.fromMsg(PublicKey.fromBytes(getPkBytes()), getMessageBytes());
        const infoFromBuffers: AggregationInfo = AggregationInfo.fromBuffers([PublicKey.fromBytes(getPkBytes())], [getMessageHash()], [Uint8Array.from([1])]);
        const pks: PublicKey[] = info.getPublicKeys();
        const messageHashes: Uint8Array[] = info.getMessageHashes();
        const exponents: Uint8Array[] = info.getExponents();
        deepStrictEqual(pks[0].serialize(), getPkBytes());
        deepStrictEqual(messageHashes[0], getMessageHash());
        deepStrictEqual(exponents[0], Uint8Array.from([1]));
        infoFromHash.delete();
        info.delete();
        infoFromBuffers.delete();
        pks.forEach(pk => pk.delete());
    });

    it('ExtendedPrivateKey', () => {
        strictEqual(ExtendedPrivateKey.EXTENDED_PRIVATE_KEY_SIZE, 77);
        const esk: ExtendedPrivateKey = ExtendedPrivateKey.fromSeed(getSkSeed());
        ExtendedPrivateKey.fromBytes(getEskBytes());
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
        privateChild.delete();
        publicChild.delete();
        chainCode.delete();
        sk.delete();
        pk.delete();
        epk.delete();
    });

    it('ExtendedPublicKey', () => {
        strictEqual(ExtendedPublicKey.VERSION, 1);
        strictEqual(ExtendedPublicKey.EXTENDED_PUBLIC_KEY_SIZE, 93);
        const epk: ExtendedPublicKey = ExtendedPublicKey.fromBytes(getEpkBytes());
        const publicChild: ExtendedPublicKey = epk.publicChild(1);
        const version: number = epk.getVersion();
        const depth: number = epk.getDepth();
        const parentFingerprint: number = epk.getParentFingerprint();
        const childNumber: number = epk.getChildNumber();
        const pk: PublicKey = epk.getPublicKey();
        const chainCode: ChainCode = epk.getChainCode();
        const bytes: Uint8Array = epk.serialize();
        epk.delete();
        publicChild.delete();
        pk.delete();
        chainCode.delete();
    });

    it('ChainCode', () => {
        strictEqual(ChainCode.CHAIN_CODE_SIZE, 32);
        const chainCode: ChainCode = ChainCode.fromBytes(getChainCodeBytes());
        const bytes: Uint8Array = chainCode.serialize();
        chainCode.delete();
    });

    it('Threshold', () => {
        const commitments = [
            PublicKey.fromBytes(Uint8Array.from(Buffer.from('93075db5c398bd2682dfab816a920023e8c0337a42fafc93c0bfab937400b6e7dafa5e456f2fa127979ff9c9a140127b', 'hex'))),
            PublicKey.fromBytes(Uint8Array.from(Buffer.from('1304180c71f137a1dc4c39c6e997285f55d9dd11f53c52f8fc7702a5b08f529190ffc01b8b6b28b64ee9704f26ca02c3', 'hex'))),
        ];
        const fragments = [
            PrivateKey.fromBytes(Uint8Array.from(Buffer.from('0b5205ed2c9aa86391dc8c7de15efa868073d83fb782f92de81e3d21916e296e', 'hex')), false),
            PrivateKey.fromBytes(Uint8Array.from(Buffer.from('56720e3ca7a2d6856fa16ef94eb2c2957066b849cea8a4da7fde0613efbc5401', 'hex')), false),
            PrivateKey.fromBytes(Uint8Array.from(Buffer.from('49d151bb34da1f1957077e231e7cdf564f418b74cb9b3b1c751714cb649631c3', 'hex')), false),
        ];
        const sk: PrivateKey = Threshold.create(commitments, fragments, 2, 3);
        const sig: InsecureSignature = Threshold.signWithCoefficient(sk, Uint8Array.from([1, 2, 3]), 2, [1, 3]);
        const aggSig: InsecureSignature = Threshold.aggregateUnitSigs([], Uint8Array.from([1, 2, 3]), [1, 2]);
        const isValid: boolean = Threshold.verifySecretFragment(1, sk, [], 3);
        sk.delete();
        sig.delete();
        aggSig.delete();
    });

    it('GROUP_ORDER', () => {
        strictEqual(GROUP_ORDER, '73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001');
    });

    it('DHKeyExchange', () => {
        const sk = PrivateKey.fromSeed(getSkSeed());
        const pk = PublicKey.fromBytes(getPkBytes());
        const result: PublicKey = DHKeyExchange(sk, pk);
        strictEqual(result.serialize().length, PublicKey.PUBLIC_KEY_SIZE);
        sk.delete();
        pk.delete();
        result.delete();
    });
});