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
}
