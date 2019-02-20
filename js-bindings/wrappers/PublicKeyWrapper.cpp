//
// Created by anton on 12.02.19.
//

#include "PublicKeyWrapper.h"
#include "../helpers.h"

using namespace emscripten;

namespace js_wrappers {
    PublicKeyWrapper::PublicKeyWrapper(PublicKey &publicKey) : wrappedPublicKey(publicKey) {}

    PublicKeyWrapper PublicKeyWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        PublicKey pk = PublicKey::FromBytes(bytes.data());
        return PublicKeyWrapper(pk);
    }

    PublicKeyWrapper PublicKeyWrapper::Aggregate(val pubKeysWrappers) {
        std::vector<PublicKeyWrapper> keyWrappers = helpers::fromJSArray<PublicKeyWrapper>(pubKeysWrappers);
        std::vector<PublicKey> pubKeys;
        for (auto &keyWrapper : keyWrappers) {
            pubKeys.push_back(keyWrapper.GetWrappedKey());
        }
        PublicKey aggregatedPk = PublicKey::Aggregate(pubKeys);
        return PublicKeyWrapper(aggregatedPk);
    }

    val PublicKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrappedPublicKey.Serialize());
    }

    uint32_t PublicKeyWrapper::GetFingerprint() const {
        return wrappedPublicKey.GetFingerprint();
    }

    PublicKey PublicKeyWrapper::GetWrappedKey() const {
        return wrappedPublicKey;
    }
}