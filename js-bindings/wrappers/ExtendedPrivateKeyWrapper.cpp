//
// Created by anton on 21.02.19.
//

#include "ExtendedPrivateKeyWrapper.h"

namespace js_wrappers {
    ExtendedPrivateKeyWrapper::ExtendedPrivateKeyWrapper(ExtendedPrivateKey &extendedPrivateKey) : JSWrapper(
            extendedPrivateKey) {};

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
        ExtendedPrivateKey esk = wrapped.PrivateChild(i);
        return ExtendedPrivateKeyWrapper(esk);
    }

    ExtendedPublicKeyWrapper ExtendedPrivateKeyWrapper::PublicChild(uint32_t i) const {
        ExtendedPublicKey epk = wrapped.PublicChild(i);
        return ExtendedPublicKeyWrapper(epk);
    };

    uint32_t ExtendedPrivateKeyWrapper::GetVersion() const {
        return wrapped.GetVersion();
    };

    uint8_t ExtendedPrivateKeyWrapper::GetDepth() const {
        return wrapped.GetDepth();
    };

    uint32_t ExtendedPrivateKeyWrapper::GetParentFingerprint() const {
        return wrapped.GetParentFingerprint();
    };

    uint32_t ExtendedPrivateKeyWrapper::GetChildNumber() const {
        return wrapped.GetChildNumber();
    };

    ChainCodeWrapper ExtendedPrivateKeyWrapper::GetChainCode() const {
        ChainCode chainCode = wrapped.GetChainCode();
        return ChainCodeWrapper(chainCode);
    };

    PrivateKeyWrapper ExtendedPrivateKeyWrapper::GetPrivateKey() const {
        PrivateKey sk = wrapped.GetPrivateKey();
        return PrivateKeyWrapper(sk);
    }

    PublicKeyWrapper ExtendedPrivateKeyWrapper::GetPublicKey() const {
        PublicKey pk = wrapped.GetPublicKey();
        return PublicKeyWrapper(pk);
    }

    ExtendedPublicKeyWrapper ExtendedPrivateKeyWrapper::GetExtendedPublicKey() const {
        ExtendedPublicKey pk = wrapped.GetExtendedPublicKey();
        return ExtendedPublicKeyWrapper(pk);
    }

    val ExtendedPrivateKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrapped.Serialize());
    }
}