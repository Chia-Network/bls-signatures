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

#ifndef BLS_AGGREGATIONINFOWRAPPER_H
#define BLS_AGGREGATIONINFOWRAPPER_H

#include "emscripten/val.h"
#include "../../src/aggregationinfo.hpp"
#include "../../src/bls.hpp"
#include "../helpers.h"
#include "PublicKeyWrapper.h"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class AggregationInfoWrapper : public JSWrapper<AggregationInfo> {
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
    };
}  // namespace js_wrappers

#endif //BLS_AGGREGATIONINFOWRAPPER_H
