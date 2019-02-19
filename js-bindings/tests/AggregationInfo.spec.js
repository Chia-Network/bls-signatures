const {AggregationInfo, PrivateKey, Signature, PublicKey} = require('../../js_build/js-bindings/blsjs');
const assert = require('assert');
const crypto = require('crypto');

function getSeed() {
    return Buffer.from([1,2,3,4,5,6,7,8,9]);
}

describe('AggregationInfo', () => {
   it('Should be able to serialize and deserialize data correctly', () => {
       const privateKey = PrivateKey.fromSeed(getSeed());
       const message = Buffer.from('Hello world', 'utf8');
       const sig = privateKey.sign(message);
       assert(sig.verify());

       const info = sig.getAggregationInfo();
       const pubKeyFromInfo = PublicKey.fromBytes(info.getPublicKeysBuffers()[0]);

       const serializedKeyFromInfo = pubKeyFromInfo.serialize();
       const serializedKeyFromPrivateKey = privateKey.getPublicKey().serialize();

       const messageHash = crypto
           .createHash('sha256')
           .update(message)
           .digest();
       const messageHashFromInfo = info.getMessageHashes()[0];

       assert.deepStrictEqual(serializedKeyFromInfo, serializedKeyFromPrivateKey);
       assert.deepStrictEqual(messageHash, messageHashFromInfo);

       const restoredInfo = AggregationInfo.fromBuffers(
           info.getPublicKeysBuffers(),
           info.getMessageHashes(),
           info.getExponents()
       );

       assert.deepStrictEqual(restoredInfo.getPublicKeysBuffers()[0].toString('hex'), info.getPublicKeysBuffers()[0].toString('hex'));
       assert.deepStrictEqual(restoredInfo.getExponents(), info.getExponents());
       assert.deepStrictEqual(restoredInfo.getMessageHashes()[0].toString('hex'), info.getMessageHashes()[0].toString('hex'));
   });
});