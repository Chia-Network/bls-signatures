//
// Created by anton on 11.02.19.
//

#ifndef BLS_PRIVATEKEYWRAPPER_H
#define BLS_PRIVATEKEYWRAPPER_H

#include "emscripten/val.h"
#include "../../src/privatekey.hpp"
#include "SignatureWrapper.h"
#include "PublicKeyWrapper.h"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PrivateKeyWrapper {
    public:
        static PrivateKeyWrapper FromSeed(val buffer);
        static PrivateKeyWrapper FromBytes(val buffer, bool modOrder);
        static PrivateKeyWrapper Aggregate(val privateKeysBuffers, val publicKeysBuffers);

        val Serialize() const;
        SignatureWrapper Sign(val messageBuffer) const;
        SignatureWrapper SignPrehashed(val messageHashBuffer) const;
        PublicKeyWrapper GetPublicKey() const;
        // Insecure signatures does not contain aggregation info
        // InsecureSignature SignInsecure(val messageBuffer) const;
        // InsecureSignature SignInsecurePrehashed(val messageHashBuffer) const;
    private:
        explicit PrivateKeyWrapper(PrivateKey& privateKey);
        PrivateKey wrappedPrivateKey;
    };
}


#endif //BLS_PRIVATEKEYWRAPPER_H
