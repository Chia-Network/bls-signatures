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
#include "wrappers/SchemeMPLWrapper.h"
#include "wrappers/UtilWrapper.h"

using namespace emscripten;

namespace js_wrappers {
EMSCRIPTEN_BINDINGS(blsjs) {
    class_<SchemeMPLWrapper<AugSchemeMPL>>("AugSchemeMPL")
        .class_function("sk_to_g1", &SchemeMPLWrapper<AugSchemeMPL>::SkToG1)
        .class_function("key_gen", &SchemeMPLWrapper<AugSchemeMPL>::KeyGen);

    class_<SchemeMPLWrapper<BasicSchemeMPL>>("BasicSchemeMPL")
        .class_function("sk_to_g1", &SchemeMPLWrapper<BasicSchemeMPL>::SkToG1)
        .class_function("key_gen", &SchemeMPLWrapper<BasicSchemeMPL>::KeyGen);

    class_<SchemeMPLWrapper<PopSchemeMPL>>("PopSchemeMPL")
        .class_function("sk_to_g1", &SchemeMPLWrapper<PopSchemeMPL>::SkToG1)
        .class_function("key_gen", &SchemeMPLWrapper<PopSchemeMPL>::KeyGen);

    class_<G1ElementWrapper>("G1Element")
        .class_property("SIZE", &G1ElementWrapper::SIZE)
        .class_function("fromBytes", &G1ElementWrapper::FromBytes)
        .function("serialize", &G1ElementWrapper::Serialize);

    class_<G2ElementWrapper>("G2Element")
        .class_property("SIZE", &G2ElementWrapper::SIZE)
        .class_function("fromBytes", &G2ElementWrapper::FromBytes)
        .function("serialize", &G2ElementWrapper::Serialize);

    class_<PrivateKeyWrapper>("PrivateKey")
        .class_property("PRIVATE_KEY_SIZE", &PrivateKeyWrapper::PRIVATE_KEY_SIZE)
        .class_function("fromBytes", &PrivateKeyWrapper::FromBytes)
        .class_function("aggregate", &PrivateKeyWrapper::Aggregate)
        .function("serialize", &PrivateKeyWrapper::Serialize)
        .function("get_g1", &PrivateKeyWrapper::GetG1);

    class_<UtilWrapper>("Util")
        .class_function("hash256", &UtilWrapper::Hash256);
};
}  // namespace js_wrappers
