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

#include <emscripten/bind.h>
#include "wrappers/PrivateKeyWrapper.h"
#include "wrappers/ExtendedPrivateKeyWrapper.h"

using namespace emscripten;
using namespace js_wrappers;

EMSCRIPTEN_BINDINGS(blsjs) {
    class_<PrivateKeyWrapper>("PrivateKey")
        .class_function("fromSeed", &PrivateKeyWrapper::FromSeed)
        .class_function("fromBytes", &PrivateKeyWrapper::FromBytes)
        .class_function("aggregate", &PrivateKeyWrapper::Aggregate)
        .function("serialize", &PrivateKeyWrapper::Serialize)
        .function("sign", &PrivateKeyWrapper::Sign)
        .function("signPrehashed", &PrivateKeyWrapper::SignPrehashed)
        .function("getPublicKey", &PrivateKeyWrapper::GetPublicKey);

    class_<SignatureWrapper>("Signature")
        .class_function("fromBytes", &SignatureWrapper::FromBytes)
        .class_function("fromBytesAndAggregationInfo", &SignatureWrapper::FromBytesAndAggregationInfo)
        .class_function("aggregateSigs", &SignatureWrapper::AggregateSigs)
        .function("serialize", &SignatureWrapper::Serialize)
        .function("verify", &SignatureWrapper::Verify)
        .function("getAggregationInfo", &SignatureWrapper::GetAggregationInfo)
        .function("setAggregationInfo", &SignatureWrapper::SetAggregationInfo);
        //.function("divideBy", &SignatureWrapper::DivideBy)

    class_<PublicKeyWrapper>("PublicKey")
        .class_function("fromBytes", &PublicKeyWrapper::FromBytes)
        .class_function("aggregate", &PublicKeyWrapper::Aggregate)
        .function("getFingerprint", &PublicKeyWrapper::GetFingerprint)
        .function("serialize", &PublicKeyWrapper::Serialize);

    class_<AggregationInfoWrapper>("AggregationInfo")
        .class_function("fromMsgHash", &AggregationInfoWrapper::FromMsgHash)
        .class_function("fromMsg", &AggregationInfoWrapper::FromMsg)
        .class_function("fromBuffers", &AggregationInfoWrapper::FromBuffers)
        .function("getPublicKeys", &AggregationInfoWrapper::GetPubKeys)
        .function("getMessageHashes", &AggregationInfoWrapper::GetMessageHashes)
        .function("getExponents", &AggregationInfoWrapper::GetExponents);

    class_<ExtendedPrivateKeyWrapper>("ExtendedPrivateKey")
        .class_function("fromSeed", &ExtendedPrivateKeyWrapper::FromSeed, allow_raw_pointers())
        .class_function("fromBytes", &ExtendedPrivateKeyWrapper::FromBytes, allow_raw_pointers())
        .function("privateChild", &ExtendedPrivateKeyWrapper::PrivateChild)
        .function("publicChild", &ExtendedPrivateKeyWrapper::PublicChild)
        .function("getVersion", &ExtendedPrivateKeyWrapper::GetVersion)
        .function("getDepth", &ExtendedPrivateKeyWrapper::GetDepth)
        .function("getParentFingerprint", &ExtendedPrivateKeyWrapper::GetParentFingerprint)
        .function("getChildNumber", &ExtendedPrivateKeyWrapper::GetChildNumber)
        .function("getChainCode", &ExtendedPrivateKeyWrapper::GetChainCode)
        .function("getPrivateKey", &ExtendedPrivateKeyWrapper::GetPrivateKey)
        .function("getPublicKey", &ExtendedPrivateKeyWrapper::GetPublicKey)
        .function("getExtendedPublicKey", &ExtendedPrivateKeyWrapper::GetExtendedPublicKey);

    class_<ExtendedPublicKeyWrapper>("ExtendedPublicKey")
        .class_function("fromBytes", &ExtendedPublicKeyWrapper::FromBytes)
        .function("publicChild", &ExtendedPublicKeyWrapper::PublicChild)
        .function("getVersion", &ExtendedPublicKey::GetVersion)
        .function("getDepth", &ExtendedPublicKeyWrapper::GetDepth)
        .function("getParentFingerprint", &ExtendedPublicKeyWrapper::GetParentFingerprint)
        .function("getChildNumber", &ExtendedPublicKeyWrapper::GetChildNumber)
        .function("getChainCode", &ExtendedPublicKeyWrapper::GetChainCode)
        .function("getPublicKey", &ExtendedPublicKey::GetPublicKey)
        .function("serialize", &ExtendedPublicKeyWrapper::Serialize);
//
//    class_<ChainCode>("ChainCode")
//        .property("CHAIN_CODE_KEY_SIZE")
//        .class_function("fromBytes", &ChainCode::FromBytes)
//        .function("serialize", &ChainCode::Serialize);
};
