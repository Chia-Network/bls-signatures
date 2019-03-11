const assert = require('assert').strict;
const { ExtendedPrivateKey } = require('../');

function getSeed() {
    return Uint8Array.from([1, 50, 6, 244, 24, 199, 1, 25]);
}

describe('ExtendedPrivateKey', () => {
    it('Should derive correctly', () => {
        const seed = getSeed();
        const esk = ExtendedPrivateKey.fromSeed(seed);
        assert.equal(esk.getPublicKey().getFingerprint(), 0xa4700b27);

        let chainCode = esk.getChainCode().serialize();
        assert.equal(Buffer.from(chainCode).toString('hex'), 'd8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3');

        const esk77 = esk.privateChild(2147483725);
        chainCode = esk77.getChainCode().serialize();
        assert.equal(Buffer.from(chainCode).toString('hex'), 'f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b');
        assert.equal(esk77.getPrivateKey().getPublicKey().getFingerprint(), 0xa8063dcf);

        assert.equal(esk.privateChild(3)
            .privateChild(17)
            .getPublicKey()
            .getFingerprint(), 0xff26a31f);
        assert.equal(esk.getExtendedPublicKey()
            .publicChild(3)
            .publicChild(17)
            .getPublicKey()
            .getFingerprint(), 0xff26a31f);
    });
});