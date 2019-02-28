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

#include "ThresholdWrapper.h"

namespace js_wrappers {
    PrivateKeyWrapper ThresholdWrapper::Create(val pubKeyWrappersArray, val privateKeyWrappers, size_t threshold,
                                               size_t playersCount) {
        std::vector<PublicKeyWrapper> pubKeyWrappers = helpers::fromJSArray<PublicKeyWrapper>(pubKeyWrappersArray);
        std::vector<PublicKey> commitement;

    }

    InsecureSignatureWrapper ThresholdWrapper::SignWithCoefficient(const PrivateKeyWrapper &sk, val msgBuffer,
                                                                   size_t playerIndex, val players) {

    }

    InsecureSignatureWrapper ThresholdWrapper::AggregateUnitSigs(val insecureSignatures, val messageBuffer,
                                                                 val players) {

    }

    val ThresholdWrapper::LagrangeCoeffsAtZero(val players) {

    }

    val ThresholdWrapper::InterpolateAtZero(val X, val Y, size_t T) {

    }

    bool ThresholdWrapper::VerifySecretFragment(size_t playerIndex, js_wrappers::PrivateKeyWrapper secretFragment,
                                                val publicKeyWrappers, size_t threshold) {

    }
}