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
        explicit PublicKeyWrapper(PublicKey& publicKey);
        static PublicKeyWrapper FromBytes(val buffer);
//        static PublicKeyWrapper AggregateInsecure(val pubKeys);
//        static PublicKeyWrapper Aggregate(val pubKeys);

        val Serialize() const;
        uint32_t GetFingerprint() const;

    private:
        PublicKey wrapperPublicKey;
    };
}

#endif //BLS_PUBLICKEYWRAPPER_H
