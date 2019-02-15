const assert = require('assert');

const {PublicKey, PrivateKey} = require('../../js_build/js-bindings/blsjs');

function getPublicKeyFixture() {
    return {
        buffer: Buffer.from('1790635de8740e9a6a6b15fb6b72f3a16afa0973d971979b6ba54761d6e2502c50db76f4d26143f05459a42cfd520d44', 'hex'),
        fingerprint: 0xddad59bb
    }
}

function getPublicKeysArray() {
    return [
        Buffer.from('02a8d2aaa6a5e2e08d4b8d406aaf0121a2fc2088ed12431e6b0663028da9ac5922c9ea91cde7dd74b7d795580acc7a61', 'hex'),
        Buffer.from('056e742478d4e95e708b8ae0d487f94099b769cb7df4c674dc0c10fbbe7d175603d090ac6064aeeb249a00ba6b3d85eb', 'hex'),
    ];
}

describe('PublicKey', () => {
    describe(".fromBytes", () => {
        it('Should create a public key from bytes', () => {
            const pk = PublicKey.fromBytes(getPublicKeyFixture().buffer);
            assert(pk instanceof PublicKey);
        });
    });

    describe(".aggregate", () => {
        it('Should aggregate keys if keys array contains more than one key', () => {
            throw new Error('Not implemented');
            const aggregatedKey = PublicKey.aggregate(getPublicKeysArray());
            assert(aggregatedKey instanceof PublicKey);
        });
    });

    describe("#serialize", () => {
        it('Should serialize key to the same buffer', () => {
            const pk = PublicKey.fromBytes(getPublicKeyFixture().buffer);
            const serialized = pk.serialize();
            assert.deepStrictEqual(serialized, getPublicKeyFixture().buffer);
        });
    });

    describe("getFingerprint", () => {
        it('Should get correct fingerprint', () => {
            const pk = PublicKey.fromBytes(getPublicKeyFixture().buffer);
            const fingerprint = pk.getFingerprint();
            assert.strictEqual(fingerprint, getPublicKeyFixture().fingerprint);
        });
    });
});