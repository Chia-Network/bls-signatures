//
// Created by anton on 21.02.19.
//

#include "ExtendedPublicKeyWrapper.h"

namespace js_wrappers {
    ExtendedPublicKeyWrapper::ExtendedPublicKeyWrapper(ExtendedPublicKey &extendedPublicKey) : wrappedPublicKey(extendedPublicKey) {};
    ExtendedPublicKeyWrapper ExtendedPublicKeyWrapper::FromBytes(val serializedBuffer) {
        std::vector<uint8_t> serialized = helpers::toVector(serializedBuffer);
        ExtendedPublicKey pk = ExtendedPublicKey::FromBytes(serialized.data());
        return ExtendedPublicKeyWrapper(pk);
    };

    ExtendedPublicKeyWrapper ExtendedPublicKeyWrapper::PublicChild(uint32_t i) const {
        ExtendedPublicKey pk = wrappedPublicKey.PublicChild(i);
        return ExtendedPublicKeyWrapper(pk);
    };

    uint32_t ExtendedPublicKeyWrapper::GetVersion() const {
        return wrappedPublicKey.GetVersion();
    };
    uint8_t ExtendedPublicKeyWrapper::GetDepth() const {
        return wrappedPublicKey.GetDepth();
    };
    uint32_t ExtendedPublicKeyWrapper::GetParentFingerprint() const {
        return wrappedPublicKey.GetParentFingerprint();
    };
    uint32_t ExtendedPublicKeyWrapper::GetChildNumber() const {
        return wrappedPublicKey.GetChildNumber();
    };

    // ChainCodeWrapper GetChainCode() const;
    PublicKeyWrapper ExtendedPublicKeyWrapper::GetPublicKey() const {
        PublicKey pk = wrappedPublicKey.GetPublicKey();
        return PublicKeyWrapper(pk);
    };

    val ExtendedPublicKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrappedPublicKey.Serialize());
    };
}