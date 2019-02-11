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

#include "wrappers/PrivateKeyWrapper.cpp"
#include "../src/bls.hpp"

using namespace emscripten;
using namespace js_wrappers;

EMSCRIPTEN_BINDINGS(blsjs) {
    class_<PrivateKeyWrapper>("PrivateKey")
            .class_function("fromSeed", &PrivateKeyWrapper::FromSeed)
            .class_function("fromBytes", &PrivateKeyWrapper::FromBytes)
            .function("serialize", &PrivateKeyWrapper::Serialize);
//        .class_function("aggregate", &PrivateKeyWrapper::Aggregate)
//        .function("sign", &PrivateKeyWrapper::Sign)
//        .function("signPrehashed", &PrivateKeyWrapper::SignPrehashed)


//    class_<ExtendedPrivateKey>("ExtendedPrivateKey")
//        .class_function("fromSeed", &ExtendedPrivateKey::FromSeed, allow_raw_pointers())
//        .class_function("fromBytes", &ExtendedPrivateKey::FromBytes, allow_raw_pointers())
//        .function("privateChild", &ExtendedPrivateKey::PrivateChild)
//        .function("publicChild", &ExtendedPrivateKey::PublicChild)
//        .function("getVersion", &ExtendedPrivateKey::GetVersion)
//        .function("getDepth", &ExtendedPrivateKey::GetDepth)
//        .function("getParentFingerprint", &ExtendedPrivateKey::GetParentFingerprint)
//        .function("getChildNumber", &ExtendedPrivateKey::GetChildNumber)
//        .function("getChainCode", &ExtendedPrivateKey::GetChainCode)
//        .function("getPrivateKey", &ExtendedPrivateKey::GetPrivateKey)
//        .function("getPublicKey", &ExtendedPrivateKey::GetPublicKey)
//        .function("getExtendedPublicKey", &ExtendedPrivateKey::GetExtendedPublicKey);
//    // TODO: add serialize here

//
//    class_<ExtendedPublicKey>("ExtendedPublicKey")
//        .property("EXTENDED_PUBLIC_KEY_SIZE", &ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE)
//        .class_function("fromBytes", &ExtendedPublicKey::FromBytes)
//        .function("publicChild", &ExtendedPublicKey::PublicChild)
//        .function("getVersion", &ExtendedPublicKey::GetVersion)
//        .function("getDepth", &ExtendedPublicKey::GetDepth)
//        .function("getParentFingerprint", &ExtendedPublicKey::GetParentFingerprint)
//        .function("getChildNumber", &ExtendedPublicKey::GetChildNumber)
//        .function("getChainCode", &ExtendedPublicKey::GetChainCode)
//        .function("getPublicKey", &ExtendedPublicKey::GetPublicKey)
//        .function("serialize", &ExtendedPublicKey::Serialize);
//
//    class_<ChainCode>("ChainCode")
//        .property("CHAIN_CODE_KEY_SIZE")
//        .class_function("fromBytes", &ChainCode::FromBytes)
//        .function("serialize", &ChainCode::Serialize);
//
//    class_<Signature>("Signature")
//        .property("SIGNATURE_SIZE", &Signature::SIGNATURE_SIZE)
//        .class_function("fromBytes", &Signature::FromBytes)
//        .class_function("aggregateSigs", &Signature::AggregateSigs)
//        .function("serialize", &Signature::Serialize)
//        .function("verify", &Signature::Verify)
//        .function("divideBy", &Signature::DivideBy)
//        .function("getAggregationInfo", &Signature::GetAggregationInfo)
//        .function("setAggregationInfo", &Signature::SetAggregationInfo);
//
//    class_<AggregationInfo>("AggregationInfo")
//        .class_function("fromMsgHash", &AggregationInfo::FromMsgHash)
//        .class_function("fromMsg", &AggregationInfo::FromMsg)
//        .class_function("mergeInfos", &AggregationInfo::MergeInfos)
//        .class_function("getPubKeys", &AggregationInfo::GetPubKey)
//        .function("getMessageHashes", &AggregationInfo::GetMessageHashes);
//
//    //TODO: check serialize method. It should be a bit more complicated, look at the python binding for the example
//    class_<PrivateKey>("PrivateKey")
//        .class_function("fromSeed", &PrivateKey::FromSeed, allow_raw_pointers())
//        .class_function("fromBytes", &PrivateKey::FromBytes, allow_raw_pointers())
//        .class_function("aggregate", &PrivateKey::Aggregate)
//        .function("sign", &PrivateKey::Sign)
//        .function("signPrehashed", &PrivateKey::SignPrehashed);
    //        .function("serialize", &PrivateKey::Serialize)
    //        .property("PRIVATE_KEY_SIZE", &PrivateKey::PRIVATE_KEY_SIZE)
//
//    class_<PublicKey>("PublicKey")
//        .property("PUBLIC_KEY_SIZE", &PublicKey::PUBLIC_KEY_SIZE)
//        .class_function("fromBytes", &PublicKey::FromBytes)
//        .class_function("aggregate", &PublicKey::Aggregate)
//        .function("getFingerprint", &PublicKey::GetFingerprint)
//        .function("serialize", &PublicKey::Serialize);
};
