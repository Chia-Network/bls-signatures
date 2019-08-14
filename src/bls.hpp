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

#ifndef SRC_BLS_HPP_
#define SRC_BLS_HPP_

#include <vector>
#include <map>
#include <string>
#include <stdexcept>

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "publickey.hpp"
#include "privatekey.hpp"
#include "signature.hpp"
#include "extendedprivatekey.hpp"
#include "aggregationinfo.hpp"
#include "threshold.hpp"

#include "relic.h"
#include "relic_test.h"

namespace bls {

/*
 * Principal class for verification and signature aggregation.
 * Include this file to use the library.
 */
class BLS {
 public:
    // Order of g1, g2, and gt. Private keys are in {0, GROUP_ORDER}.
    static const char GROUP_ORDER[];
    static const size_t MESSAGE_HASH_LEN = 32;
    static mclBnG1 mclG1gen;

    // Initializes the BLS library (called automatically)
    static bool Init();

    static void SetSecureAllocator(Util::SecureAllocCallback allocCb, Util::SecureFreeCallback freeCb);

    // Used for secure aggregation
    static void HashPubKeys(
            bn_t* output,
            size_t numOutputs,
            std::vector<uint8_t*> const &serPubKeys,
            std::vector<size_t> const &sortedIndices);

    static PublicKey DHKeyExchange(const PrivateKey& privKey, const PublicKey& pubKey);

    static void CheckRelicErrors();
    static void CheckRelicErrorsInvalidArgument();
};
} // end namespace bls

#endif  // SRC_BLS_HPP_
