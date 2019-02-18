//
// Created by anton on 11.02.19.
//

#ifndef BLS_SIGNATUREWRAPPER_H
#define BLS_SIGNATUREWRAPPER_H

#include "emscripten/val.h"
#include "../../src/signature.hpp"
#include "AggregationInfoWrapper.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    class SignatureWrapper {
    public:
        static SignatureWrapper FromSignature(Signature &signature);

        static SignatureWrapper FromBytes(val buffer);

        // Unlike the original method, this method also needs to know corresponding aggregation infos
        // for each signature, since serialized signature doesn't contain
        static SignatureWrapper AggregateSigs(val signatureWrappers);

        static SignatureWrapper FromBytesAndAggregationInfo(val buffer, const AggregationInfoWrapper &infoWrapper);

        bool Verify() const;

        val Serialize() const;

        AggregationInfoWrapper GetAggregationInfo() const;

        void SetAggregationInfo(AggregationInfoWrapper &newAggregationInfo);

    private:
        explicit SignatureWrapper(Signature &signature);

        Signature wrappedSignature;

        static std::vector<Signature> GetRawSignatures(val signatureWrappers);
    };
}

#endif //BLS_SIGNATUREWRAPPER_H
