//
// Created by anton on 11.02.19.
//

#include "PrivateKeyWrapper.h"
#include "../helpers.h"
#include "SignatureWrapper.h"

using namespace emscripten;

namespace js_wrappers {
    PrivateKeyWrapper::PrivateKeyWrapper(PrivateKey &privateKey) : wrappedPrivateKey(privateKey) {}

    PrivateKeyWrapper PrivateKeyWrapper::FromSeed(val buffer) {
        std::vector<uint8_t> bytes = helpers::jsBufferToVector(buffer);
        PrivateKey pk = PrivateKey::FromSeed(bytes.data(), bytes.size());
        PrivateKeyWrapper pw = PrivateKeyWrapper(pk);
        return pw;
    }

    PrivateKeyWrapper PrivateKeyWrapper::Aggregate(val privateKeysBuffers, val publicKeysBuffers) {
        std::vector<std::vector<uint8_t>> publicKeysVectors = helpers::buffersArrayToVector(publicKeysBuffers);
        std::vector<std::vector<uint8_t>> privateKeysVectors = helpers::buffersArrayToVector(privateKeysBuffers);

        std::vector<PublicKey> pubKeys;
        auto pkCount = publicKeysVectors.size();
        for(unsigned i = 0; i < pkCount; ++i) {
            pubKeys.push_back(PublicKey::FromBytes(publicKeysVectors[i].data()));
        }

        std::vector<PrivateKey> privateKeys;
        auto skCount = privateKeys.size();
        for(unsigned i = 0; i < skCount; ++i) {
            privateKeys.push_back(PrivateKey::FromBytes(privateKeysVectors[i].data()));
        }

        PrivateKey aggregatedPk = PrivateKey::Aggregate(privateKeys, pubKeys);
        PrivateKeyWrapper pw = PrivateKeyWrapper(aggregatedPk);
        return pw;
    }

    PrivateKeyWrapper PrivateKeyWrapper::FromBytes(val buffer, bool modOrder) {
        std::vector<uint8_t> bytes = helpers::jsBufferToVector(buffer);
        PrivateKey pk = PrivateKey::FromBytes(bytes.data(), modOrder);
        PrivateKeyWrapper pw = PrivateKeyWrapper(pk);
        return pw;
    }

    val PrivateKeyWrapper::Serialize() const {
        std::vector<uint8_t> pk = wrappedPrivateKey.Serialize();
        val buffer = helpers::vectorToJSBuffer(pk);
        return buffer;
    }

    SignatureWrapper PrivateKeyWrapper::Sign(val messageBuffer) const {
        std::vector<uint8_t> message = helpers::jsBufferToVector(messageBuffer);
        Signature signature = wrappedPrivateKey.Sign(message.data(), message.size());
        SignatureWrapper sw = SignatureWrapper::FromSignature(signature);
        return sw;
    }

    SignatureWrapper PrivateKeyWrapper::SignPrehashed(val messageHashBuffer) const {
        std::vector<uint8_t> hash = helpers::jsBufferToVector(messageHashBuffer);
        Signature signature = wrappedPrivateKey.SignPrehashed(hash.data());
        SignatureWrapper sw = SignatureWrapper::FromSignature(signature);
        return sw;
    }

    PublicKeyWrapper PrivateKeyWrapper::GetPublicKey() const {
        PublicKey pk = wrappedPrivateKey.GetPublicKey();
        PublicKeyWrapper pw = PublicKeyWrapper(pk);
        return pw;
    }
}
