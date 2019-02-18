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

    SignatureWrapper SignatureWrapper::FromBytesAndAggregationInfo(val buffer, const AggregationInfoWrapper &infoWrapper) {
        AggregationInfo info = infoWrapper.GetWrappedInfo();
        std::vector<uint8_t> bytes = helpers::jsBufferToVector(buffer);
        Signature sig = Signature::FromBytes(bytes.data(), info);
        return SignatureWrapper(sig);
    }

    SignatureWrapper SignatureWrapper::AggregateSigs(val signatureWrappers) {
        std::vector<Signature> signatures = SignatureWrapper::GetRawSignatures(signatureWrappers);
        printf("Sigs constructed \n");
        Signature aggregatedSignature = Signature::AggregateSigs(signatures);
        printf("Sigs aggregated \n");
        SignatureWrapper sw = SignatureWrapper(aggregatedSignature);
        printf("Wrapper created \n");
        return sw;
    }

    val SignatureWrapper::Serialize() const {
        return helpers::vectorToJSBuffer(wrappedSignature.Serialize());
    }

    bool SignatureWrapper::Verify() const {
        return wrappedSignature.Verify();
    }

    AggregationInfoWrapper SignatureWrapper::GetAggregationInfo() const {
        const AggregationInfo *info = wrappedSignature.GetAggregationInfo();
        AggregationInfo in = AggregationInfo(*info);
        AggregationInfoWrapper aw = AggregationInfoWrapper(in);
        return aw;
    }

    void SignatureWrapper::SetAggregationInfo(AggregationInfoWrapper &newAggregationInfo) {
        wrappedSignature.SetAggregationInfo(newAggregationInfo.GetWrappedInfo());
    }

    std::vector<Signature> SignatureWrapper::GetRawSignatures(val signatureWrappersArray) {
        std::vector<Signature> sigs;
        auto l = signatureWrappersArray["length"].as<unsigned>();
        for (unsigned i = 0; i < l; ++i) {
            // Getting signature bytes without aggregation info
            val wrappedSig = signatureWrappersArray[i];
            std::vector<uint8_t> serializedSig = helpers::jsBufferToVector(wrappedSig.call<val>("serialize"));

            // Getting data from the aggregation info
            val wrappedAggregationInfo = wrappedSig.call<val>("getAggregationInfo");
            val messageHashes = wrappedAggregationInfo.call<val>("getMessageHashes");
            val pubKeys = wrappedAggregationInfo.call<val>("GetPubKeysBuffers");
            val exponents = wrappedAggregationInfo.call<val>("getExponents");

            // Converting JS arrays to cpp vectors
            printf("%d \n", 10);
            std::vector<uint8_t*> messageHashesVector = helpers::jsBuffersArrayToByteArraysVector(messageHashes);
            std::vector<std::vector<uint8_t>> pubKeysBuffers = helpers::jsBuffersArrayToVector(pubKeys);
            std::vector<PublicKey> pubKeysVector;
            printf("%d \n", 11);
            for (unsigned j = 0; j<pubKeysBuffers.size(); j++) {
                pubKeysVector.push_back(PublicKey::FromBytes(pubKeysBuffers[j].data()));
            }
            printf("%d \n", 12);
            std::vector<bn_t*> exponentsVector = helpers::jsBuffersArrayToBnVector(exponents);

            printf("%d \n", 13);
            // Constructing aggregation info and restoring data from it
            AggregationInfo info = AggregationInfo::FromVectors(pubKeysVector, messageHashesVector, exponentsVector);
            printf("%d \n", 14);
            Signature sig = Signature::FromBytes(serializedSig.data(), info);

            printf("%d \n", 15);
            sigs.push_back(sig);
        }
        return sigs;
    }
}