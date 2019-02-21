//
// Created by anton on 21.02.19.
//

#ifndef BLS_EXTENDEDPRIVATEKEYWRAPPER_H
#define BLS_EXTENDEDPRIVATEKEYWRAPPER_H

#include "emscripten/val.h"
#include "../helpers.h"
#include "../../src/extendedprivatekey.hpp"
#include "PrivateKeyWrapper.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    class ExtendedPrivateKeyWrapper {
    public:
        explicit ExtendedPrivateKeyWrapper(ExtendedPrivateKey &extendedPrivateKey);

        static ExtendedPrivateKeyWrapper FromSeed(val seedBuffer);
        static ExtendedPrivateKeyWrapper FromBytes(val serializedBuffer);
        ExtendedPrivateKeyWrapper PrivateChild(uint32_t i) const;
        // ExtendedPublicKeyWrapper PublicChild(uint32_t i) const;

        uint32_t GetVersion() const;
        uint8_t GetDepth() const;
        uint32_t GetParentFingerprint() const;
        uint32_t GetChildNumber() const;

        // ChainCodeWrapper GetChainCode() const;
        PrivateKeyWrapper GetPrivateKey() const;

        PublicKeyWrapper GetPublicKey() const;
        // ExtendedPublicKeyWrapper GetExtendedPublicKey() const;

        val Serialize() const;
    private:
        ExtendedPrivateKey wrappedPrivateKey;
    };
}


#endif //BLS_EXTENDEDPRIVATEKEYWRAPPER_H
