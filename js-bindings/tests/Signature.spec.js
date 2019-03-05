const assert = require('assert');
const {Signature, PublicKey, PrivateKey, AggregationInfo} = require('../');

function getSignatureHex() {
    return '006d0a8661db762a94be51be85efb1199f62dfc3f8fa8c9f003d02fdc69b281e689a54928b9adce98a8471a889c55af40c9bd7b7339c00f6f8bf871d132cfa5cf4e9b11f7ce05acafbb24c2db82b7f6193ee954f5167a2a46e3daecf4a007609';
}

function getSignatureBuffer() {
    return Buffer.from(getSignatureHex(), 'hex');
}

function getAggregationInfo() {
    return {
        publicKeys: [Uint8Array.from(Buffer.from('02a8d2aaa6a5e2e08d4b8d406aaf0121a2fc2088ed12431e6b0663028da9ac5922c9ea91cde7dd74b7d795580acc7a61', 'hex'))],
        messageHashes: [Uint8Array.from(Buffer.from('c7495fe7e1d49086a1966a2020e01b4f36ed71c456b6aa5e684ad6c3631890af', 'hex'))],
        exponents: [Uint8Array.from(Buffer.from('01', 'hex'))]
    };
}

describe('Signature', () => {
    describe('Integration', () => {
        it('Should verify signatures', function () {
            this.timeout(10000);
            const message = Uint8Array.from([100, 2, 254, 88, 90, 45, 23]);
            const seed1 = Uint8Array.from([1, 2, 3, 4, 5]);
            const seed2 = Uint8Array.from([3, 4, 5, 6, 7]);
            const seed3 = Uint8Array.from([4, 5, 6, 7, 8]);

            const privateKey1 = PrivateKey.fromSeed(seed1);
            const privateKey2 = PrivateKey.fromSeed(seed2);
            const privateKey3 = PrivateKey.fromSeed(seed3);

            const publicKey1 = privateKey1.getPublicKey();
            const publicKey2 = privateKey2.getPublicKey();
            const publicKey3 = privateKey3.getPublicKey();

            const sig1 = privateKey1.sign(message);
            const sig2 = privateKey2.sign(message);
            const sig3 = privateKey3.sign(message);

            assert(sig1.verify(), 'Signature 1 is not verifiable');
            assert(sig2.verify(), 'Signature 2 is not verifiable');
            assert(sig3.verify(), 'Signature 3 is not verifiable');

            const aggregatedSignature = Signature.aggregateSigs([sig1, sig2, sig3]);
            assert(aggregatedSignature.verify(), 'Aggregated sig is not verified');

            const aggregatedPubKey = PublicKey.aggregate([publicKey1, publicKey2, publicKey3]);

            const aggregationInfo = AggregationInfo.fromMsg(aggregatedPubKey, message);

            aggregatedSignature.setAggregationInfo(aggregationInfo);
            assert(aggregatedSignature.verify());
        });
    });
    describe('.fromBytes', () => {
        it('Should create verifiable signature from bytes', () => {
            const sig = Signature.fromBytes(getSignatureBuffer());
            assert.strictEqual(Buffer.from(sig.serialize()).toString('hex'), getSignatureHex());
            // Since there is no aggregation info, it's impossible to verify sig
            assert.strictEqual(sig.verify(), false);
        });
    });
    describe('.fromBytesAndAggregationInfo', () => {
        it('Should create verifiable signature', () => {
            const pk = PrivateKey.fromSeed(Uint8Array.from([1, 2, 3, 4, 5]));
            const sig = pk.sign(Uint8Array.from([100, 2, 254, 88, 90, 45, 23]));
            const info = sig.getAggregationInfo();
            const restoredSig = Signature.fromBytesAndAggregationInfo(
                sig.serialize(),
                sig.getAggregationInfo()
            );
            const restoredInfo = restoredSig.getAggregationInfo();
            assert(restoredSig instanceof Signature);
            assert(restoredSig.verify());
            assert.deepStrictEqual(info.getPublicKeys()[0].serialize(), restoredInfo.getPublicKeys()[0].serialize());
            assert.deepStrictEqual(info.getMessageHashes()[0], restoredInfo.getMessageHashes()[0]);
            assert.deepStrictEqual(info.getExponents()[0], restoredInfo.getExponents()[0]);
        });
    });
    describe('.aggregateSigs', () => {

    });
    describe('#serialize', () => {
        it('Should serialize signature to Buffer', () => {
            const pk = PrivateKey.fromSeed(Uint8Array.from([1, 2, 3, 4, 5]));
            const sig = pk.sign(Uint8Array.from([100, 2, 254, 88, 90, 45, 23]));
            assert(sig instanceof Signature);
            assert.deepStrictEqual(Buffer.from(sig.serialize()).toString('hex'), getSignatureHex());
        });
    });
    describe('#verify', () => {
        it('Should return true if signature can be verified', () => {
            const pks = getAggregationInfo().publicKeys.map(buf => PublicKey.fromBytes(buf));
            const sig = Signature.fromBytesAndAggregationInfo(
                getSignatureBuffer(),
                AggregationInfo.fromBuffers(
                    pks,
                    getAggregationInfo().messageHashes,
                    getAggregationInfo().exponents
                )
            );
            assert(sig.verify());
        });
        it("Should return false if signature can't be verified", () => {
            const sk = PrivateKey.fromSeed(Buffer.from([1, 2, 3, 4, 5]));
            const pks = getAggregationInfo().publicKeys.map(buf => PublicKey.fromBytes(buf));
            const sig = sk.sign(Uint8Array.from(Buffer.from('Message')));
            const info = AggregationInfo.fromBuffers(
                pks,
                getAggregationInfo().messageHashes,
                getAggregationInfo().exponents
            );
            sig.setAggregationInfo(info);
            assert.strictEqual(sig.verify(), false);
        })
    });
});