//
// Created by anton on 21.02.19.
//

#include "ExtendedPrivateKeyWrapper.h"

namespace js_wrappers {
    ExtendedPrivateKeyWrapper::ExtendedPrivateKeyWrapper(ExtendedPrivateKey &extendedPrivateKey) : wrappedPrivateKey(extendedPrivateKey) {};

    ExtendedPrivateKeyWrapper ExtendedPrivateKeyWrapper::FromSeed(val seedBuffer) {
        std::vector<uint8_t> seed = helpers::toVector(seedBuffer);
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(seed.data(), seed.size());
        return ExtendedPrivateKeyWrapper(esk);
    }

    ExtendedPrivateKeyWrapper ExtendedPrivateKeyWrapper::FromBytes(val serializedBuffer) {
        std::vector<uint8_t> serialized = helpers::toVector(serializedBuffer);
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromBytes(serialized.data());
        return ExtendedPrivateKeyWrapper(esk);
    }

    ExtendedPrivateKeyWrapper ExtendedPrivateKeyWrapper::PrivateChild(uint32_t i) const {
        ExtendedPrivateKey esk = wrappedPrivateKey.PrivateChild(i);
        return ExtendedPrivateKeyWrapper(esk);
    }

    uint32_t ExtendedPrivateKeyWrapper::GetVersion() const {
        return wrappedPrivateKey.GetVersion();
    };
    uint8_t ExtendedPrivateKeyWrapper::GetDepth() const {
        return wrappedPrivateKey.GetDepth();
    };
    uint32_t ExtendedPrivateKeyWrapper::GetParentFingerprint() const {
        return wrappedPrivateKey.GetParentFingerprint();
    };
    uint32_t ExtendedPrivateKeyWrapper::GetChildNumber() const {
        return wrappedPrivateKey.GetChildNumber();
    };

    PrivateKeyWrapper ExtendedPrivateKeyWrapper::GetPrivateKey() const {
        PrivateKey sk = wrappedPrivateKey.GetPrivateKey();
        return PrivateKeyWrapper(sk);
    }

    PublicKeyWrapper ExtendedPrivateKeyWrapper::GetPublicKey() const {
        PublicKey pk = wrappedPrivateKey.GetPublicKey();
        return PublicKeyWrapper(pk);
    }

    emscripten::val ExtendedPrivateKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrappedPrivateKey.Serialize());
    }
}