//
// Created by anton on 21.02.19.
//

#include "ExtendedPublicKeyWrapper.h"

namespace js_wrappers {
    ExtendedPublicKeyWrapper::ExtendedPublicKeyWrapper(ExtendedPublicKey &extendedPublicKey) : JSWrapper(
            extendedPublicKey) {};

    ExtendedPublicKeyWrapper ExtendedPublicKeyWrapper::FromBytes(val serializedBuffer) {
        std::vector<uint8_t> serialized = helpers::toVector(serializedBuffer);
        ExtendedPublicKey pk = ExtendedPublicKey::FromBytes(serialized.data());
        return ExtendedPublicKeyWrapper(pk);
    };

    ExtendedPublicKeyWrapper ExtendedPublicKeyWrapper::PublicChild(uint32_t i) const {
        ExtendedPublicKey pk = wrapped.PublicChild(i);
        return ExtendedPublicKeyWrapper(pk);
    };

    uint32_t ExtendedPublicKeyWrapper::GetVersion() const {
        return wrapped.GetVersion();
    };

    uint8_t ExtendedPublicKeyWrapper::GetDepth() const {
        return wrapped.GetDepth();
    };

    uint32_t ExtendedPublicKeyWrapper::GetParentFingerprint() const {
        return wrapped.GetParentFingerprint();
    };

    uint32_t ExtendedPublicKeyWrapper::GetChildNumber() const {
        return wrapped.GetChildNumber();
    };

    ChainCodeWrapper ExtendedPublicKeyWrapper::GetChainCode() const {
        ChainCode chainCode = wrapped.GetChainCode();
        return ChainCodeWrapper(chainCode);
    };

    PublicKeyWrapper ExtendedPublicKeyWrapper::GetPublicKey() const {
        PublicKey pk = wrapped.GetPublicKey();
        return PublicKeyWrapper(pk);
    };

    val ExtendedPublicKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrapped.Serialize());
    };
}