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

#include "G1ElementWrapper.h"

namespace js_wrappers {
G1ElementWrapper::G1ElementWrapper(const G1Element &publicKey) : JSWrapper(publicKey) {}

const size_t G1ElementWrapper::SIZE = G1Element::SIZE;

std::vector <G1Element> G1ElementWrapper::Unwrap(std::vector <G1ElementWrapper> wrappers) {
    std::vector <G1Element> unwrapped;
    for (auto &wrapper : wrappers) {
        unwrapped.push_back(wrapper.GetWrappedInstance());
    }
    return unwrapped;
}

G1ElementWrapper G1ElementWrapper::FromBytes(val buffer) {
    std::vector <uint8_t> bytes = helpers::toVector(buffer);
    const bls::Bytes bytesView(bytes);
    G1Element pk = G1Element::FromBytes(bytesView);
    return G1ElementWrapper(pk);
}

val G1ElementWrapper::Serialize() const {
    return helpers::toUint8Array(wrapped.Serialize());
}

G1ElementWrapper G1ElementWrapper::Add(const G1ElementWrapper &other) {
    return G1ElementWrapper(GetWrappedInstance() + other.GetWrappedInstance());
}

uint32_t G1ElementWrapper::GetFingerprint() const {
    return wrapped.GetFingerprint();
}
}  // namespace js_wrappers
