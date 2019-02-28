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

#ifndef BLS_PUBLICKEYWRAPPER_H
#define BLS_PUBLICKEYWRAPPER_H

#include "emscripten/val.h"
#include "../../src/publickey.hpp"
#include "../helpers.h"
#include "JSWrapper.h"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PublicKeyWrapper : public JSWrapper<PublicKey> {
    public:
        explicit PublicKeyWrapper(PublicKey &publicKey);

        static std::vector<PublicKey> Unwrap(std::vector<PublicKeyWrapper> wrappers);

        static PublicKeyWrapper FromBytes(val buffer);

        static PublicKeyWrapper Aggregate(val pubKeysWrappers);

        val Serialize() const;

        uint32_t GetFingerprint() const;
    };
}

#endif //BLS_PUBLICKEYWRAPPER_H
