//
// Created by anton on 11.02.19.
//

#include "SignatureWrapper.h"
#include "../helpers.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    SignatureWrapper::SignatureWrapper(Signature &signature) : wrappedSignature(signature) {}

    SignatureWrapper SignatureWrapper::FromSignature(Signature &signature) {
        SignatureWrapper sw = SignatureWrapper(signature);
        return sw;
    }

    SignatureWrapper SignatureWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::jsBufferToVector(buffer);
        Signature sig = Signature::FromBytes(bytes.data());
        SignatureWrapper sw = SignatureWrapper(sig);
        return sw;
    }

    SignatureWrapper SignatureWrapper::AggregateSigs(val signatureBuffers) {
        std::vector<std::vector<uint8_t>> signaturesVector = helpers::buffersArrayToVector(signatureBuffers);
        std::vector<Signature> signatures;
        auto l = signaturesVector.size();
        for (unsigned i = 0; i < l; ++i) {
            signatures.push_back(Signature::FromBytes(signaturesVector[i].data()));
        }
        Signature aggregatedSignature = Signature::AggregateSigs(signatures);
        SignatureWrapper sw = SignatureWrapper(aggregatedSignature);
        return sw;
    }

    val SignatureWrapper::Serialize() const {
        return helpers::vectorToJSBuffer(wrappedSignature.Serialize());
    }

    bool SignatureWrapper::Verify() const {
        return wrappedSignature.Verify();
    }
}