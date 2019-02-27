//
// Created by anton on 25.02.19.
//

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