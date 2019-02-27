//
// Created by anton on 11.02.19.
//

#include "PrivateKeyWrapper.h"
#include "../helpers.h"

using namespace emscripten;

namespace js_wrappers {
    PrivateKeyWrapper::PrivateKeyWrapper(PrivateKey &privateKey) : JSWrapper(privateKey) {};

    PrivateKeyWrapper PrivateKeyWrapper::FromSeed(val buffer) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        PrivateKey pk = PrivateKey::FromSeed(bytes.data(), bytes.size());
        return PrivateKeyWrapper(pk);
    }

    PrivateKeyWrapper PrivateKeyWrapper::Aggregate(val privateKeysArray, val publicKeysArray) {
        std::vector<PublicKeyWrapper> publicKeysVector = helpers::fromJSArray<PublicKeyWrapper>(publicKeysArray);
        std::vector<PrivateKeyWrapper> privateKeysVector = helpers::fromJSArray<PrivateKeyWrapper>(privateKeysArray);

        std::vector<PublicKey> pubKeys;
        for (auto &publicKeyWrapper : publicKeysVector) {
            pubKeys.push_back(publicKeyWrapper.GetWrappedInstance());
        }

        std::vector<PrivateKey> privateKeys;
        for (auto &privateKeyWrapper : privateKeysVector) {
            privateKeys.push_back(privateKeyWrapper.GetWrappedInstance());
        }

        PrivateKey aggregatedPk = PrivateKey::Aggregate(privateKeys, pubKeys);
        return PrivateKeyWrapper(aggregatedPk);
    }

    PrivateKeyWrapper PrivateKeyWrapper::FromBytes(val buffer, bool modOrder) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        PrivateKey pk = PrivateKey::FromBytes(bytes.data(), modOrder);
        return PrivateKeyWrapper(pk);
    }

    val PrivateKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrapped.Serialize());
    }

    SignatureWrapper PrivateKeyWrapper::Sign(val messageBuffer) const {
        std::vector<uint8_t> message = helpers::toVector(messageBuffer);
        Signature signature = wrapped.Sign(message.data(), message.size());
        return SignatureWrapper::FromSignature(signature);
    }

    SignatureWrapper PrivateKeyWrapper::SignPrehashed(val messageHashBuffer) const {
        std::vector<uint8_t> hash = helpers::toVector(messageHashBuffer);
        Signature signature = wrapped.SignPrehashed(hash.data());
        return SignatureWrapper::FromSignature(signature);
    }

    PublicKeyWrapper PrivateKeyWrapper::GetPublicKey() const {
        PublicKey pk = wrapped.GetPublicKey();
        return PublicKeyWrapper(pk);
    }
}
