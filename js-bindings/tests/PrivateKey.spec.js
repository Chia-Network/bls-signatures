const blsSignaturesModule = require('..')();
const assert = require('assert');
const crypto = require('crypto');
const {Buffer} = require('buffer');

// Values lifted from test.js, which is ported from test.py and is a more
// primary source.
function getPkSeed() {
    return Uint8Array.from([
        0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6, 220,
        18, 102, 58, 209, 82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22
    ]);
}

function getSeedAndFinferprint() {
    var seedArray = getPkSeed();
    var seed = Buffer.from(seedArray);
    return {
        seed: seed,
        fingerprint: 3146750013
    };
}

function getPkBuffer() {
    return Uint8Array.from([
        55, 112, 145, 240, 231, 40,  70,  59,
        194, 218, 125,  84, 108, 83, 185, 246,
        184,  29, 244, 161, 204, 26, 181, 191,
        41, 197, 144, 139, 113, 81, 163,  45
    ]);
}

function getPkUint8Array() {
    return new Uint8Array(getPkBuffer());
}

let blsSignatures = null;
before((done) => {
    blsSignaturesModule.then((mod) => {
        blsSignatures = mod;
        done();
    });
});

describe('PrivateKey', () => {
    it('Should sign and verify', () => {
        const {AugSchemeMPL} = blsSignatures;

        const message1 = Uint8Array.from([1, 65, 254, 88, 90, 45, 22]);

        const sk1 = AugSchemeMPL.key_gen(getPkSeed());
        const pk1 = AugSchemeMPL.sk_to_g1(sk1);
        const sig1 = AugSchemeMPL.sign(sk1, message1);

        assert(AugSchemeMPL.verify(pk1, message1, sig1));
    });

    describe('.fromSeed', () => {
        it('Should create a private key from a seed', () => {
            const {AugSchemeMPL, PrivateKey} = blsSignatures;

            const pk = AugSchemeMPL.key_gen(getPkSeed());
            assert(pk instanceof PrivateKey);
            assert.deepStrictEqual(pk.serialize(), getPkBuffer());
        });
    });

    describe('.fromBytes', () => {
        it('Should create a private key from a Buffer', () => {
            const {PrivateKey} = blsSignatures;

            const pk = PrivateKey.from_bytes(getPkBuffer(), false);
            assert(pk instanceof PrivateKey);
            assert.deepStrictEqual(pk.serialize(), getPkBuffer());
        });
        it('Should create a private key from a Uint8Array', () => {
            const {PrivateKey} = blsSignatures;

            const pk = PrivateKey.from_bytes(getPkUint8Array(), false);
            assert(pk instanceof PrivateKey);
            assert.deepStrictEqual(pk.serialize(), getPkBuffer());
        });
    });

    describe('#serialize', () => {
        it('Should serialize key to a Buffer', () => {
            const {AugSchemeMPL} = blsSignatures;

            const pk = AugSchemeMPL.key_gen(getPkSeed());
            const serialized = pk.serialize();
            assert(serialized instanceof Uint8Array);
            assert.deepStrictEqual(serialized, getPkBuffer());
        });
    });

    describe('#sign', () => {
        it('Should return a verifiable signature', () => {
            const {AugSchemeMPL, PrivateKey, G2Element} = blsSignatures;

            const pk = PrivateKey.fromBytes(getPkBuffer(), false);
            const pubkey = AugSchemeMPL.sk_to_g1(pk);
            const message = 'Hello world';
            const messageBuffer = Uint8Array.from(Buffer.from(message, 'utf8'));
            const signature = AugSchemeMPL.sign(pk, messageBuffer);
            assert(signature instanceof G2Element);
            assert(AugSchemeMPL.verify(pubkey, messageBuffer, signature));
        });
    });

    describe('#getPublicKey', () => {
        it('Should return a public key with a verifiable fingerprint', () => {
            const {AugSchemeMPL, G1Element} = blsSignatures;

            const pk = AugSchemeMPL.key_gen(getPkSeed());
            const publicKey = AugSchemeMPL.sk_to_g1(pk);
            assert(publicKey instanceof G1Element);
            assert.strictEqual(publicKey.get_fingerprint(), getSeedAndFinferprint().fingerprint);
        });
    });
});
