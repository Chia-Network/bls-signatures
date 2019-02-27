//
// Created by anton on 15.02.19.
//

#ifndef BLS_AGGREGATIONINFOWRAPPER_H
#define BLS_AGGREGATIONINFOWRAPPER_H

#include "emscripten/val.h"
#include "../../src/aggregationinfo.hpp"
#include "PublicKeyWrapper.h"
#include "../../src/bls.hpp"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class AggregationInfoWrapper {
    public:
        explicit AggregationInfoWrapper(AggregationInfo &info);

        static AggregationInfoWrapper FromMsgHash(const PublicKeyWrapper &pkw, val messageHashBuffer);

        static AggregationInfoWrapper FromMsg(const PublicKeyWrapper &pkw, val messageBuffer);

        static AggregationInfoWrapper FromBuffers(val pubKeys, val messageHashes, val exponentBns);

        static AggregationInfo FromBuffersUnwrapped(val pubKeyWrappers, val messageHashes, val exponentBns);

//
//        static AggregationInfoWrapper MergeInfos(val infos);
//
//        void RemoveEntries(val messageBuffers, val pubKeyBuffers);
//
        val GetPubKeys() const;

        val GetMessageHashes() const;

        val GetExponents() const;
//        bool Empty() const;

        AggregationInfo GetWrappedInstance() const;

    private:
        AggregationInfo wrappedInfo;
    };
}

#endif //BLS_AGGREGATIONINFOWRAPPER_H
