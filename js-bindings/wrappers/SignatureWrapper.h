// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef BLS_SIGNATUREWRAPPER_H
#define BLS_SIGNATUREWRAPPER_H

#include "emscripten/val.h"
#include "../../src/signature.hpp"
#include "AggregationInfoWrapper.h"
#include "../helpers.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    class InsecureSignatureWrapper : public JSWrapper<InsecureSignature> {
    public:
        explicit InsecureSignatureWrapper(InsecureSignature &signature);

        static const size_t SIGNATURE_SIZE;

        static std::vector <InsecureSignature> Unwrap(std::vector <InsecureSignatureWrapper> sigWrappers);

        static InsecureSignatureWrapper FromBytes(val buffer);

        static InsecureSignatureWrapper Aggregate(val insecureSignatureWrappers);

        bool Verify(val hashesBuffers, val pubKeyWrappersArray) const;

        InsecureSignatureWrapper DivideBy(val insecureSignatureWrappers) const;

        val Serialize() const;
    };

    class SignatureWrapper : public JSWrapper<Signature> {
    public:
        explicit SignatureWrapper(Signature &signature);

        static const size_t SIGNATURE_SIZE;

        static std::vector <Signature> Unwrap(std::vector <SignatureWrapper> sigWrappers);

        static SignatureWrapper FromSignature(Signature &signature);

        static SignatureWrapper FromBytes(val buffer);

        static SignatureWrapper AggregateSigs(val signatureWrappers);

        static SignatureWrapper FromBytesAndAggregationInfo(val buffer, const AggregationInfoWrapper &infoWrapper);

        static SignatureWrapper FromInsecureSignature(InsecureSignatureWrapper signature);

        static SignatureWrapper
        FromInsecureSignatureAndInfo(InsecureSignatureWrapper signature, AggregationInfoWrapper info);

        bool Verify() const;

        val Serialize() const;

        AggregationInfoWrapper GetAggregationInfo() const;

        void SetAggregationInfo(AggregationInfoWrapper &newAggregationInfo);

        SignatureWrapper DivideBy(val signatureWrappers) const;
    };
}

#endif //BLS_SIGNATUREWRAPPER_H
