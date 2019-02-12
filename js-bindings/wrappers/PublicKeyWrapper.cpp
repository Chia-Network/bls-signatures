//
// Created by anton on 12.02.19.
//

#include "PublicKeyWrapper.h"
#include "../helpers.h"

using namespace emscripten;

namespace js_wrappers {
    PublicKeyWrapper::PublicKeyWrapper(PublicKey& publicKey) : wrapperPublicKey(publicKey) {}

    PublicKeyWrapper PublicKeyWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::jsBufferToVector(buffer);
        PublicKey pk = PublicKey::FromBytes(bytes.data());
        PublicKeyWrapper pw = PublicKeyWrapper(pk);
        return pw;
    }

    val PublicKeyWrapper::Serialize() const {
        std::vector<uint8_t> bytes = wrapperPublicKey.Serialize();
        val buffer = helpers::vectorToJSBuffer(bytes);
        return buffer;
    }

    uint32_t PublicKeyWrapper::GetFingerprint() const {
        return wrapperPublicKey.GetFingerprint();
    }
}