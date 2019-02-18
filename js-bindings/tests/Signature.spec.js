const assert = require('assert');
const { Signature, PublicKey, PrivateKey, AggregationInfo } = require('../../js_build/js-bindings/blsjs');

function getSignatureBuffer() {
    return Buffer.from('', 'hex');
}

function getTwoSigntureBuffers() {
    return {
        signatureBuffers: [],
        aggregationInfos: [],
        publicKeys: []
    }
}

describe('Signature', () => {
    it('Should verify signatures', () => {
        const message = Buffer.from([100, 2, 254, 88, 90, 45, 23]);
        const seed1 = Buffer.from([1,2,3,4,5]);
        const seed2 = Buffer.from([3,4,5,6,7]);
        const seed3 = Buffer.from([4,5,6,7,8]);

        console.log(1);

        const privateKey1 = PrivateKey.fromSeed(seed1);
        const privateKey2 = PrivateKey.fromSeed(seed2);
        const privateKey3 = PrivateKey.fromSeed(seed3);

        console.log(2);

        const publicKey1 = privateKey1.getPublicKey();
        const publicKey2 = privateKey2.getPublicKey();
        const publicKey3 = privateKey3.getPublicKey();

        console.log(3);

        const sig1 = privateKey1.sign(message);
        const sig2 = privateKey2.sign(message);
        const sig3 = privateKey3.sign(message);

        console.log(4);

        const aggregatedSignature = Signature.aggregateSigs([ sig1, sig2, sig3 ]);

        console.log(5);

        const aggregatedPubKey = PublicKey.aggregate([
            publicKey1.serialize(), publicKey2.serialize(), publicKey3.serialize()
        ]);

        console.log(6);

        const aggregationInfo = AggregationInfo.fromMsg(aggregatedPubKey, message);

        console.log(7);

        aggregatedSignature.setAggregationInfo(aggregationInfo);
        assert(aggregatedSignature.verify());
    });
    describe('.fromBytes', () => {
        it('Should create verifiable signature from bytes', () => {
            throw new Error('Not implemented');
        });
    });
    describe('.fromBytesAndAggregationInfo', () => {

    });
    describe('.aggregateSigs', () => {

    });
    describe('#serialize', () => {

    });
    describe('#verify', () => {

    });
    describe('#getAggregationInfo', () => {

    });
    describe('#setAggregationInfo', () => {

    });
});