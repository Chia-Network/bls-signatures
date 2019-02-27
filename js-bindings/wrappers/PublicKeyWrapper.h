//
// Created by anton on 12.02.19.
//

#ifndef BLS_PUBLICKEYWRAPPER_H
#define BLS_PUBLICKEYWRAPPER_H

#include "emscripten/val.h"
#include "../../src/publickey.hpp"
#include "JSWrapper.h"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PublicKeyWrapper : public JSWrapper<PublicKey> {
    public:
        explicit PublicKeyWrapper(PublicKey &publicKey);

        static std::vector<PublicKey> Unwrap(std::vector<PublicKeyWrapper> wrappers);

        static PublicKeyWrapper FromBytes(val buffer);

        static PublicKeyWrapper Aggregate(val pubKeysWrappers);

        val Serialize() const;

        uint32_t GetFingerprint() const;
    };
}

#endif //BLS_PUBLICKEYWRAPPER_H
