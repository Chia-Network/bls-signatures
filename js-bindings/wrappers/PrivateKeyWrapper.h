//
// Created by anton on 11.02.19.
//

#include "../../src/privatekey.hpp"
#include "emscripten/val.h"
#include "SignatureWrapper.cpp"

#ifndef BLS_PRIVATEKEYWRAPPER_H
#define BLS_PRIVATEKEYWRAPPER_H

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PrivateKeyWrapper {
    public:
        static PrivateKeyWrapper FromSeed(val buffer);
        static PrivateKeyWrapper FromBytes(val buffer, bool modOrder);
//        static PrivateKeyWrapper AggregateInsecure(val privateKeys);
//        static PrivateKeyWrapper Aggregate(val privateKeys, val publicKeys);

        val Serialize() const;
        SignatureWrapper Sign(val messageBuffer) const;
//        PublicKeyWrapper GetPublicKey() const;
//        InsecureSignatureWrapper SignInsecure(val hashBuffer) const;
//        InsecureSignatureWrapper SignInsecurePrehashed(val hashBuffer) const;
//        SignatureSrapper SignPrehashed(val hashBuffer) const;
    private:
        explicit PrivateKeyWrapper(PrivateKey& privateKey);
        PrivateKey wrappedPrivateKey;
    };
}


#endif //BLS_PRIVATEKEYWRAPPER_H
