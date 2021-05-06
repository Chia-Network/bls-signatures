// Copyright 2020 Chia Network Inc

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
#include "wrappers/UtilWrapper.h"

using namespace emscripten;

namespace js_wrappers {
EMSCRIPTEN_BINDINGS(blsjs) {
    class_<PrivateKeyWrapper>("PrivateKey")
        .class_property("PRIVATE_KEY_SIZE", &PrivateKeyWrapper::PRIVATE_KEY_SIZE)
        .class_function("fromBytes", &PrivateKeyWrapper::FromBytes)
        .class_function("aggregate", &PrivateKeyWrapper::Aggregate)
        .function("serialize", &PrivateKeyWrapper::Serialize)
        .function("getG1", &PrivateKeyWrapper::GetG1);

    class_<UtilWrapper>("Util")
        .class_function("hash256", &UtilWrapper::Hash256);

    class_<SignatureWrapper>("Signature")
        .class_property("SIGNATURE_SIZE", &SignatureWrapper::SIGNATURE_SIZE)
        .class_function("fromBytes", &SignatureWrapper::FromBytes)
        .class_function("aggregateSigs", &SignatureWrapper::AggregateSigs)
        .function("serialize", &SignatureWrapper::Serialize);

    class_<PublicKeyWrapper>("PublicKey")
        .class_property("PUBLIC_KEY_SIZE", &PublicKeyWrapper::PUBLIC_KEY_SIZE)
        .class_function("fromBytes", &PublicKeyWrapper::FromBytes)
        .function("getFingerprint", &PublicKeyWrapper::GetFingerprint)
        .function("serialize", &PublicKeyWrapper::Serialize);
};
}  // namespace js_wrappers
