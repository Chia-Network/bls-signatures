//
// Created by anton on 11.02.19.
//

#include "SignatureWrapper.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    InsecureSignatureWrapper::InsecureSignatureWrapper(InsecureSignature &signature) : wrappedSignature(signature) {}

    InsecureSignatureWrapper InsecureSignatureWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        InsecureSignature sig = InsecureSignature::FromBytes(bytes.data());
        return InsecureSignatureWrapper(sig);
    }

    InsecureSignatureWrapper InsecureSignatureWrapper::Aggregate(val insecureSignatureWrappers) {
        std::vector<InsecureSignatureWrapper> sigWrappers = helpers::fromJSArray<InsecureSignatureWrapper>(insecureSignatureWrappers);
        std::vector<InsecureSignature> signatures;
        for (auto &sigWrapper : sigWrappers) {
            signatures.emplace_back(sigWrapper.GetWrappedSignature());
        }
        InsecureSignature aggregatedSignature = InsecureSignature::Aggregate(signatures);
        return InsecureSignatureWrapper(aggregatedSignature);
    }

    bool InsecureSignatureWrapper::Verify(val hashesBuffers, val pubKeyWrappersArray) const {
        std::vector<std::vector<uint8_t>> hashesVectors = helpers::jsBuffersArrayToVector(hashesBuffers);
        std::vector<const uint8_t*> hashes;
        for (auto &i : hashesVectors) {
            hashes.push_back(i.data());
        }
        std::vector<PublicKeyWrapper> pubKeyWrappers = helpers::fromJSArray<PublicKeyWrapper>(pubKeyWrappersArray);
        std::vector<PublicKey> pubKeysVector;
        for (auto &pubKeyWrapper : pubKeyWrappers) {
            pubKeysVector.push_back(pubKeyWrapper.GetWrappedKey());
        }

        return wrappedSignature.Verify(hashes, pubKeysVector);
    }

    InsecureSignatureWrapper InsecureSignatureWrapper::DivideBy(val insecureSignatureWrappers) const {
        std::vector<InsecureSignatureWrapper> sigWrappers = helpers::fromJSArray<InsecureSignatureWrapper>(insecureSignatureWrappers);
        std::vector<InsecureSignature> signatures;
        for (auto &sigWrapper : sigWrappers) {
            signatures.emplace_back(sigWrapper.GetWrappedSignature());
        }
        InsecureSignature dividedSignature = wrappedSignature.DivideBy(signatures);
        return InsecureSignatureWrapper(dividedSignature);
    }

    val InsecureSignatureWrapper::Serialize() const {
        std::vector<uint8_t> bytes = wrappedSignature.Serialize();
        return helpers::toJSBuffer(bytes);
    }

    InsecureSignature InsecureSignatureWrapper::GetWrappedSignature() const {
        return wrappedSignature;
    }

    ///

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
        return SignatureWrapper(aggregatedSignature);
    }

    SignatureWrapper SignatureWrapper::FromInsecureSignature(const InsecureSignatureWrapper signature) {
        Signature sig = Signature::FromInsecureSig(signature.GetWrappedSignature());
        return SignatureWrapper(sig);
    }

    SignatureWrapper SignatureWrapper::FromInsecureSignatureAndInfo(const InsecureSignatureWrapper signature,
                                                             const AggregationInfoWrapper info) {
        Signature sig = Signature::FromInsecureSig(signature.GetWrappedSignature(), info.GetWrappedInfo());
        return SignatureWrapper(sig);
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

    SignatureWrapper SignatureWrapper::DivideBy(val signatureWrappers) const {
        std::vector<SignatureWrapper> sigWrappers = helpers::fromJSArray<SignatureWrapper>(signatureWrappers);
        std::vector<Signature> signatures;
        for (auto &sigWrapper : sigWrappers) {
            signatures.push_back(sigWrapper.GetWrappedSignature());
        }
        Signature sig = GetWrappedSignature();
        Signature dividedSig = sig.DivideBy(signatures);
        return SignatureWrapper(dividedSig);
    }

    Signature SignatureWrapper::GetWrappedSignature() const {
        return wrappedSignature;
    }

}