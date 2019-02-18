//
// Created by anton on 12.02.19.
//

#include "PublicKeyWrapper.h"
#include "../helpers.h"

using namespace emscripten;

namespace js_wrappers {
    PublicKeyWrapper::PublicKeyWrapper(PublicKey &publicKey) : wrappedPublicKey(publicKey) {}

    PublicKeyWrapper PublicKeyWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::jsBufferToVector(buffer);
        PublicKey pk = PublicKey::FromBytes(bytes.data());
        PublicKeyWrapper pw = PublicKeyWrapper(pk);
        return pw;
    }

    PublicKeyWrapper PublicKeyWrapper::Aggregate(val pubKeysBuffersArray) {
        std::vector<std::vector<uint8_t>> keys = helpers::jsBuffersArrayToVector(pubKeysBuffersArray);
        std::vector<PublicKey> pubKeys;
        auto l = keys.size();
        for (unsigned i = 0; i < l; ++i) {
            pubKeys.push_back(PublicKey::FromBytes(keys[i].data()));
        }
        PublicKey aggregatedPk = PublicKey::Aggregate(pubKeys);
        PublicKeyWrapper pw = PublicKeyWrapper(aggregatedPk);
        return pw;
    }

    val PublicKeyWrapper::Serialize() const {
        std::vector<uint8_t> bytes = wrappedPublicKey.Serialize();
        val buffer = helpers::vectorToJSBuffer(bytes);
        return buffer;
    }

    uint32_t PublicKeyWrapper::GetFingerprint() const {
        return wrappedPublicKey.GetFingerprint();
    }

    PublicKey PublicKeyWrapper::GetWrappedKey() const {
        return wrappedPublicKey;
    }
}