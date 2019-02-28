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

#ifndef BLS_EXTENDEDPRIVATEKEYWRAPPER_H
#define BLS_EXTENDEDPRIVATEKEYWRAPPER_H

#include "emscripten/val.h"
#include "../helpers.h"
#include "../../src/extendedprivatekey.hpp"
#include "PrivateKeyWrapper.h"
#include "ExtendedPublicKeyWrapper.h"
#include "ChainCodeWrapper.h"

using namespace bls;
using namespace emscripten;

namespace js_wrappers {
    class ExtendedPrivateKeyWrapper: public JSWrapper<ExtendedPrivateKey> {
    public:
        explicit ExtendedPrivateKeyWrapper(ExtendedPrivateKey &extendedPrivateKey);

        static ExtendedPrivateKeyWrapper FromSeed(val seedBuffer);

        static ExtendedPrivateKeyWrapper FromBytes(val serializedBuffer);

        ExtendedPrivateKeyWrapper PrivateChild(uint32_t i) const;

        ExtendedPublicKeyWrapper PublicChild(uint32_t i) const;

        uint32_t GetVersion() const;

        uint8_t GetDepth() const;

        uint32_t GetParentFingerprint() const;

        uint32_t GetChildNumber() const;

        ChainCodeWrapper GetChainCode() const;

        PrivateKeyWrapper GetPrivateKey() const;

        PublicKeyWrapper GetPublicKey() const;

        ExtendedPublicKeyWrapper GetExtendedPublicKey() const;

        val Serialize() const;
    };
}


#endif //BLS_EXTENDEDPRIVATEKEYWRAPPER_H
