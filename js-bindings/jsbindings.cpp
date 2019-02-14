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
// #include "wrappers/SignatureWrapper.h"

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
        .function("serialize", &SignatureWrapper::Serialize)
        .function("verify", &SignatureWrapper::Verify);
//        .class_function("aggregateSigs", &SignatureWrapper::AggregateSigs)
//        .function("divideBy", &SignatureWrapper::DivideBy)
//        .function("getAggregationInfo", &SignatureWrapper::GetAggregationInfo)
//        .function("setAggregationInfo", &SignatureWrapper::SetAggregationInfo);

    class_<PublicKeyWrapper>("PublicKey")
        .class_function("fromBytes", &PublicKeyWrapper::FromBytes)
        .class_function("aggregate", &PublicKeyWrapper::Aggregate)
        .function("getFingerprint", &PublicKeyWrapper::GetFingerprint)
        .function("serialize", &PublicKeyWrapper::Serialize);

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
//    class_<AggregationInfo>("AggregationInfo")
//        .class_function("fromMsgHash", &AggregationInfo::FromMsgHash)
//        .class_function("fromMsg", &AggregationInfo::FromMsg)
//        .class_function("mergeInfos", &AggregationInfo::MergeInfos)
//        .class_function("getPubKeys", &AggregationInfo::GetPubKey)
//        .function("getMessageHashes", &AggregationInfo::GetMessageHashes);
};
