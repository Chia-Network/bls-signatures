//
// Created by anton on 15.02.19.
//

#include "AggregationInfoWrapper.h"
#include "emscripten/val.h"
#include "../helpers.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    AggregationInfoWrapper::AggregationInfoWrapper(AggregationInfo &info) : wrappedInfo(info) {}

    AggregationInfoWrapper AggregationInfoWrapper::FromMsgHash(const PublicKeyWrapper &pkw, val messageHashBuffer) {
        PublicKey pk = pkw.GetWrappedKey();
        std::vector<uint8_t> messageHash = helpers::jsBufferToVector(messageHashBuffer);
        AggregationInfo info = AggregationInfo::FromMsgHash(pk, messageHash.data());
        return AggregationInfoWrapper(info);
    }

    AggregationInfoWrapper AggregationInfoWrapper::FromMsg(const PublicKeyWrapper &pkw, val messageHashBuffer) {
        PublicKey pk = pkw.GetWrappedKey();
        std::vector<uint8_t> message = helpers::jsBufferToVector(messageHashBuffer);
        AggregationInfo info = AggregationInfo::FromMsg(pk, message.data(), message.size());
        return AggregationInfoWrapper(info);
    }

    val AggregationInfoWrapper::GetPubKeysBuffers() const {
        std::vector<PublicKey> pubKeys = wrappedInfo.GetPubKeys();
        std::vector<std::vector<uint8_t>> serializedKeys;
        for (unsigned i = 0; i < pubKeys.size(); i++) {
            serializedKeys.push_back(pubKeys[i].Serialize());
        }
        val pubKeysArray = helpers::vectorOfVectorsToBuffersArray(serializedKeys);
        return pubKeysArray;
    }

    val AggregationInfoWrapper::GetMessageHashes() const {
        std::vector<uint8_t*> messageHashesPointers = wrappedInfo.GetMessageHashes();
        val messageHashes = helpers::byteArraysVectorToJsBuffersArray(messageHashesPointers, BLS::MESSAGE_HASH_LEN);
        return messageHashes;
    }

    val AggregationInfoWrapper::GetExponents() const {
        std::vector<PublicKey> pubKeys = wrappedInfo.GetPubKeys();
        std::vector<uint8_t*> messageHashes = wrappedInfo.GetMessageHashes();
        std::vector<val> exponents;
        auto l = pubKeys.size();
        for (unsigned i = 0; i < l; ++i) {
            bn_t *exponent;
            wrappedInfo.GetExponent(exponent, messageHashes[i], pubKeys[i]);
            val serializedExponent = helpers::bnToJsBuffer(*exponent);
            exponents.push_back(serializedExponent);
        }
        val jsExponents = helpers::valVectorToJsArray(exponents);
        return jsExponents;
    }

    AggregationInfo AggregationInfoWrapper::GetWrappedInfo() const {
        return wrappedInfo;
    }
}