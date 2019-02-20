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
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        Signature sig = Signature::FromBytes(bytes.data());
        SignatureWrapper sw = SignatureWrapper(sig);
        return sw;
    }

    SignatureWrapper
    SignatureWrapper::FromBytesAndAggregationInfo(val buffer, const AggregationInfoWrapper &infoWrapper) {
        AggregationInfo info = infoWrapper.GetWrappedInfo();
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        Signature sig = Signature::FromBytes(bytes.data(), info);
        return SignatureWrapper(sig);
    }

    SignatureWrapper SignatureWrapper::AggregateSigs(val signatureWrappers) {
        std::vector<SignatureWrapper> sigWrappers = helpers::fromJSArray<SignatureWrapper>(signatureWrappers);
        std::vector<Signature> signatures;
        for (auto &sigWrapper : sigWrappers) {
            signatures.push_back(sigWrapper.GetWrappedSignature());
        }
        Signature aggregatedSignature = Signature::AggregateSigs(signatures);
        SignatureWrapper sw = SignatureWrapper(aggregatedSignature);
        return sw;
    }

    val SignatureWrapper::Serialize() const {
        return helpers::toJSBuffer(wrappedSignature.Serialize());
    }

    bool SignatureWrapper::Verify() const {
        return wrappedSignature.Verify();
    }

    AggregationInfoWrapper SignatureWrapper::GetAggregationInfo() const {
        AggregationInfo in = AggregationInfo(*wrappedSignature.GetAggregationInfo());
        AggregationInfoWrapper aw = AggregationInfoWrapper(in);
        return aw;
    }

    void SignatureWrapper::SetAggregationInfo(AggregationInfoWrapper &newAggregationInfo) {
        wrappedSignature.SetAggregationInfo(newAggregationInfo.GetWrappedInfo());
    }

    Signature SignatureWrapper::GetWrappedSignature() const {
        return wrappedSignature;
    }

}