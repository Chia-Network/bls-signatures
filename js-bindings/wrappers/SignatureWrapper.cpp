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

#include "SignatureWrapper.h"

namespace js_wrappers {
SignatureWrapper::SignatureWrapper(const Signature &signature) : JSWrapper(signature) {}

const size_t SignatureWrapper::SIGNATURE_SIZE = Signature::SIZE;


std::vector <Signature> SignatureWrapper::Unwrap(std::vector <js_wrappers::SignatureWrapper> sigWrappers) {
    std::vector <Signature> signatures;
    for (auto &sigWrapper : sigWrappers) {
        signatures.push_back(sigWrapper.GetWrappedInstance());
    }
    return signatures;
}

SignatureWrapper SignatureWrapper::FromSignature(const Signature &signature) {
    return SignatureWrapper(signature);
}

SignatureWrapper SignatureWrapper::FromBytes(val buffer) {
    std::vector <uint8_t> bytes = helpers::toVector(buffer);
    const bls::Bytes bytesView(bytes);
    Signature sig = Signature::FromBytes(bytesView);
    return SignatureWrapper(sig);
}

SignatureWrapper SignatureWrapper::AggregateSigs(val signatureWrappers) {
    std::vector <Signature> signatures = SignatureWrapper::Unwrap(
            helpers::toVectorFromJSArray<SignatureWrapper>(signatureWrappers));
    return SignatureWrapper::FromSignature(BasicSchemeMPL().Aggregate(signatures));
}

val SignatureWrapper::Serialize() const {
    return helpers::toUint8Array(wrapped.Serialize());
}
}  // namespace js_wrappers
