//
// Created by anton on 11.02.19.
//

#ifndef BLS_SIGNATUREWRAPPER_H
#define BLS_SIGNATUREWRAPPER_H

#include "emscripten/val.h"
#include "../../src/signature.hpp"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    class SignatureWrapper {
        public:
            static SignatureWrapper FromSignature(Signature& signature);
            static SignatureWrapper FromBytes(val buffer);
            // static SignatureWrapper FromBytes(val buffer, const AggregationInfoWrapper &info);
            // static SignatureWrapper FromInsecureSig(const InsecureSignature& sig);
            // static SignatureWrapper FromInsecureSig(const InsecureSignature& sig, const AggregationInfo &info);
            //static SignatureWrapper AggregateSigs(val signatures);

            bool Verify() const;
            val Serialize() const;
            //Signature DivideBy(val signatures) const;
            //AggregationInfoWrapper GetAggregationInfo() const;
            //void SetAggregationInfo(const AggregationInfoWrapper *newAggregationInfo);
            //InsecureSignatureWrapper GetInsecureSig() const;

        private:
            explicit SignatureWrapper(Signature& signature);
            Signature wrappedSignature;
    };
}

#endif //BLS_SIGNATUREWRAPPER_H
