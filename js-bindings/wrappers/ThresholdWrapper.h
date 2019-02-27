//
// Created by anton on 25.02.19.
//

#ifndef BLS_THRESHOLDWRAPPER_H
#define BLS_THRESHOLDWRAPPER_H

#include "../../src/bls.hpp"
#include "../../src/threshold.hpp"
#include "PrivateKeyWrapper.h"
#include "emscripten/val.h"

namespace js_wrappers {
    class ThresholdWrapper {
    public:
        static PrivateKeyWrapper
        Create(val pubKeyWrappersArray, val privateKeyWrappers, size_t threshold, size_t playersCount);

        static InsecureSignatureWrapper
        SignWithCoefficient(const PrivateKeyWrapper &sk, val msgBuffer, size_t playerIndex, val players);

        static InsecureSignatureWrapper AggregateUnitSigs(val insecureSignatures, val messageBuffer, val players);

        static val LagrangeCoeffsAtZero(val players);

        static val InterpolateAtZero(val X, val Y, size_t T);

        static bool VerifySecretFragment(size_t playerIndex, PrivateKeyWrapper secretFragment, val publicKeyWrappers,
                                         size_t threshold);
    };

}

#endif //BLS_THRESHOLDWRAPPER_H
