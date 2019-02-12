const { PrivateKey, Signature } = require('../../js_build/js-bindings/blsjs');
const assert = require('assert');

function getPkSeed() {
    return Buffer.from([
        0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6, 220,
        18, 102, 58, 209, 82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22
    ]);
}

function getPkBuffer() {
    return Buffer.from([
        84, 61, 124, 70, 203, 191, 91, 170, 188, 74, 176, 22, 97, 250, 169, 26,
        105, 59, 39, 4, 246, 103, 227, 53, 133, 228, 214, 59, 165, 6, 158, 39
    ]);
}

function getPkUint8Array() {
    return new Uint8Array(getPkBuffer());
}

describe('PrivateKey', () => {
    describe('.fromSeed', () => {
        it('Should create a private key from a seed', () => {
            const pk = PrivateKey.fromSeed(getPkSeed());
            assert(pk instanceof PrivateKey);
            assert.deepStrictEqual(pk.serialize(), getPkBuffer());
        });
    });
    describe('.fromBytes', () => {
        it('Should create a private key from a Buffer', () => {
            const pk = PrivateKey.fromBytes(getPkBuffer(), false);
            assert(pk instanceof PrivateKey);
            assert.deepStrictEqual(pk.serialize(), getPkBuffer());
        });
        it('Should create a private key from a Uint8Array', () => {
            const pk = PrivateKey.fromBytes(getPkUint8Array(), false);
            assert(pk instanceof PrivateKey);
            assert.deepStrictEqual(pk.serialize(), getPkBuffer());
        });
        it('Should throw an error if the buffer size is wrong', () => {
            const uintArr = getPkUint8Array().slice(0, 21);
            assert.throws(() => {
                const pk = PrivateKey.fromBytes(uintArr, false);
            });
        });
    });

    describe('#serialize', () => {
        it('Should serialize key to a Uint8Array', () => {
            const pk = PrivateKey.fromSeed(getPkSeed());
            const serialized = pk.serialize();
            assert(serialized instanceof Uint8Array);
            assert.deepStrictEqual(serialized, getPkBuffer());
        });
    });

    describe('#sign', () => {
        it('Should return a signature', () => {
            const pk = PrivateKey.fromBytes(getPkUint8Array(), false);
            const signature = pk.sign(Buffer.from('Hello world', 'utf8'));
            assert(signature instanceof Signature);
        });
    })
});