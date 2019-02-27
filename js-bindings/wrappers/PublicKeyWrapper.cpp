#include <utility>

//
// Created by anton on 12.02.19.
//

#include "PublicKeyWrapper.h"
#include "../helpers.h"

using namespace emscripten;

namespace js_wrappers {
    PublicKeyWrapper::PublicKeyWrapper(PublicKey &publicKey) : JSWrapper(publicKey) {}

    std::vector<PublicKey> PublicKeyWrapper::Unwrap(std::vector<PublicKeyWrapper> wrappers) {
        std::vector<PublicKey> unwrapped;
        for (auto &wrapper : wrappers) {
            unwrapped.push_back(wrapper.GetWrappedInstance());
        }
        return unwrapped;
    }

    PublicKeyWrapper PublicKeyWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        PublicKey pk = PublicKey::FromBytes(bytes.data());
        return PublicKeyWrapper(pk);
    }

    PublicKeyWrapper PublicKeyWrapper::Aggregate(val pubKeysWrappers) {
        std::vector<PublicKey> pubKeys = PublicKeyWrapper::Unwrap(
                helpers::fromJSArray<PublicKeyWrapper>(pubKeysWrappers));
        PublicKey aggregatedPk = PublicKey::Aggregate(pubKeys);
        return PublicKeyWrapper(aggregatedPk);
    }

    val PublicKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrapped.Serialize());
    }

    uint32_t PublicKeyWrapper::GetFingerprint() const {
        return wrapped.GetFingerprint();
    }
}