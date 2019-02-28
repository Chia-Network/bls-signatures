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

#include "PublicKeyWrapper.h"
#include "../helpers.h"

using namespace emscripten;

namespace js_wrappers {
    PublicKeyWrapper::PublicKeyWrapper(PublicKey &publicKey) : JSWrapper(publicKey) {}

    std::vector<PublicKey> PublicKeyWrapper::Unwrap(std::vector<PublicKeyWrapper> wrappers) {
        std::vector<PublicKey> unwrapped;
        for (auto &wrapper : wrappers) {
            unwrapped.push_back(wrapper.GetWrappedInstance());
        }
        return unwrapped;
    }

    PublicKeyWrapper PublicKeyWrapper::FromBytes(val buffer) {
        std::vector<uint8_t> bytes = helpers::toVector(buffer);
        PublicKey pk = PublicKey::FromBytes(bytes.data());
        return PublicKeyWrapper(pk);
    }

    PublicKeyWrapper PublicKeyWrapper::Aggregate(val pubKeysWrappers) {
        std::vector<PublicKey> pubKeys = PublicKeyWrapper::Unwrap(
                helpers::fromJSArray<PublicKeyWrapper>(pubKeysWrappers));
        PublicKey aggregatedPk = PublicKey::Aggregate(pubKeys);
        return PublicKeyWrapper(aggregatedPk);
    }

    val PublicKeyWrapper::Serialize() const {
        return helpers::toJSBuffer(wrapped.Serialize());
    }

    uint32_t PublicKeyWrapper::GetFingerprint() const {
        return wrapped.GetFingerprint();
    }
}