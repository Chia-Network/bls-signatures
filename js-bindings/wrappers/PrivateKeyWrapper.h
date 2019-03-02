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

#ifndef BLS_PRIVATEKEYWRAPPER_H
#define BLS_PRIVATEKEYWRAPPER_H

#include "emscripten/val.h"
#include "../../src/privatekey.hpp"
#include "SignatureWrapper.h"
#include "PublicKeyWrapper.h"
#include "JSWrapper.h"

using namespace emscripten;
using namespace bls;

namespace js_wrappers {
    class PrivateKeyWrapper : public JSWrapper<PrivateKey> {
    public:
        explicit PrivateKeyWrapper(PrivateKey &privateKey);

        static std::vector<PrivateKey> Unwrap(std::vector<PrivateKeyWrapper> wrappers);

        static PrivateKeyWrapper FromSeed(val buffer);

        static PrivateKeyWrapper FromBytes(val buffer, bool modOrder);

        static PrivateKeyWrapper Aggregate(val privateKeysArray, val publicKeysArray);

        static PrivateKeyWrapper AggregateInsecure(val privateKeysArray);

        val Serialize() const;

        SignatureWrapper Sign(val messageBuffer) const;

        InsecureSignatureWrapper SignInsecure(val messageBuffer) const;

        SignatureWrapper SignPrehashed(val messageHashBuffer) const;

        PublicKeyWrapper GetPublicKey() const;
    };
}


#endif //BLS_PRIVATEKEYWRAPPER_H
