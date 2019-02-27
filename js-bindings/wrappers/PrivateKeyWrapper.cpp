//
// Created by anton on 11.02.19.
//

#include "PrivateKeyWrapper.h"

using namespace emscripten;

namespace js_wrappers {
    PrivateKeyWrapper::PrivateKeyWrapper(PrivateKey &privateKey) : JSWrapper(privateKey) {};

    std::vector<PrivateKey> PrivateKeyWrapper::Unwrap(std::vector<PrivateKeyWrapper> wrappers) {
        std::vector<PrivateKey> unwrapped;
        for (auto &wrapper : wrappers) {
            unwrapped.push_back(wrapper.GetWrappedInstance());
        }
        return unwrapped;
    }

    PrivateKeyWrapper PrivateKeyWrapper::FromSeed(val buffer) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        PrivateKey pk = PrivateKey::FromSeed(bytes.data(), bytes.size());
        return PrivateKeyWrapper(pk);
    }

    PrivateKeyWrapper PrivateKeyWrapper::Aggregate(val privateKeysArray, val publicKeysArray) {
        std::vector<PublicKey> pubKeys = PublicKeyWrapper::Unwrap(
                helpers::fromJSArray<PublicKeyWrapper>(publicKeysArray));
        std::vector<PrivateKey> privateKeys = PrivateKeyWrapper::Unwrap(
                helpers::fromJSArray<PrivateKeyWrapper>(privateKeysArray));

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
