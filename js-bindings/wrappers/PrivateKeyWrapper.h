//
// Created by anton on 11.02.19.
//

#ifndef BLS_PRIVATEKEYWRAPPER_H
#define BLS_PRIVATEKEYWRAPPER_H

#include "emscripten/val.h"
#include "../../src/privatekey.hpp"
#include "SignatureWrapper.h"
#include "PublicKeyWrapper.h"
#include "JSWrapper.h"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PrivateKeyWrapper: public JSWrapper<PrivateKey> {
    public:
        explicit PrivateKeyWrapper(PrivateKey &privateKey);

        static PrivateKeyWrapper FromSeed(val buffer);

        static PrivateKeyWrapper FromBytes(val buffer, bool modOrder);

        static PrivateKeyWrapper Aggregate(val privateKeysBuffers, val publicKeysBuffers);

        val Serialize() const;

        SignatureWrapper Sign(val messageBuffer) const;

        SignatureWrapper SignPrehashed(val messageHashBuffer) const;

        PublicKeyWrapper GetPublicKey() const;
    };
}


#endif //BLS_PRIVATEKEYWRAPPER_H
