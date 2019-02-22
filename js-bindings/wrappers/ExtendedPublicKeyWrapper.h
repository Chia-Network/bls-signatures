//
// Created by anton on 21.02.19.
//

#ifndef BLS_EXTENDEDPUBLICKEYWRAPPER_H
#define BLS_EXTENDEDPUBLICKEYWRAPPER_H

#include "../helpers.h"
#include "PublicKeyWrapper.h"
#include "emscripten/val.h"

namespace js_wrappers {
    class ExtendedPublicKeyWrapper {
    public:
        explicit ExtendedPublicKeyWrapper(ExtendedPublicKey &extendedPublicKey);
        static ExtendedPublicKeyWrapper FromBytes(val serializedBuffer);

        ExtendedPublicKeyWrapper PublicChild(uint32_t i) const;

        uint32_t GetVersion() const;
        uint8_t GetDepth() const;
        uint32_t GetParentFingerprint() const;
        uint32_t GetChildNumber() const;

        // ChainCodeWrapper GetChainCode() const;
        PublicKeyWrapper GetPublicKey() const;

        val Serialize() const;

    private:
        ExtendedPublicKey wrappedPublicKey;
    };
}


#endif //BLS_EXTENDEDPUBLICKEYWRAPPER_H
