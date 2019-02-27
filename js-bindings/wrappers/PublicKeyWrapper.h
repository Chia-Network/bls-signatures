//
// Created by anton on 12.02.19.
//

#ifndef BLS_PUBLICKEYWRAPPER_H
#define BLS_PUBLICKEYWRAPPER_H

#include "emscripten/val.h"
#include "../../src/publickey.hpp"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PublicKeyWrapper {
    public:
        explicit PublicKeyWrapper(PublicKey &publicKey);

        static std::vector<PublicKey> GetWrappedComponents(std::vector<PublicKeyWrapper> wrappers);

        static PublicKeyWrapper FromBytes(val buffer);

        static PublicKeyWrapper Aggregate(val pubKeysWrappers);

        val Serialize() const;

        uint32_t GetFingerprint() const;

        PublicKey GetWrappedInstance() const;

    private:
        PublicKey wrapped;
    };
}

#endif //BLS_PUBLICKEYWRAPPER_H
