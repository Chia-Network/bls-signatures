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
#include "blspublickey.hpp"
#include "blsprivatekey.hpp"
#include "blssignature.hpp"
#include "extendedprivatekey.hpp"
#include "aggregationinfo.hpp"

namespace relic {
    #include "relic.h"
    #include "relic_test.h"
}

/*
 * Principal class for verification and signature aggregation.
 * Include this file to use the library.
 */
class BLS {
 public:
    // Order of g1, g2, and gt. Private keys are in {0, GROUP_ORDER}.
    static const char GROUP_ORDER[];
    static const size_t MESSAGE_HASH_LEN = 32;

    // Initializes the BLS library manually
    static bool Init();
    // Asserts the BLS library is initialized
    static void AssertInitialized();
    // Cleans the BLS library
    static void Clean();

    // Securely aggregates many signatures on messages, some of
    // which may be identical. The signature can then be verified
    // using VerifyAggregate. The returned signature contains
    // information on how the aggregation was done (AggragationInfo).
    static BLSSignature AggregateSigs(
            std::vector<BLSSignature> const &sigs);

    // Verifies a single or aggregate signature.
    // Performs two pairing operations, sig must contain information on
    // how aggregation was performed (AggregationInfo). The Aggregation
    // Info contains all the public keys and messages required.
    static bool Verify(const BLSSignature &sig);

    // Creates a combined public/private key that can be used to create
    // or verify aggregate signatures on the same message
    static BLSPublicKey AggregatePubKeys(std::vector<BLSPublicKey> const &pubKeys,
            bool secure);
    static BLSPrivateKey AggregatePrivKeys(
            std::vector<BLSPrivateKey> const &privateKeys,
            std::vector<BLSPublicKey> const &pubKeys,
            bool secure);

    // Used for secure aggregation
    static void HashPubKeys(
            relic::bn_t* output,
            size_t numOutputs,
            std::vector<BLSPublicKey> const &pubKeys);

 private:
    // Efficiently aggregates many signatures using the simple aggregation
    // method. Performs only n g2 operations.
    static BLSSignature AggregateSigsSimple(
            std::vector<BLSSignature> const &sigs);

    // Aggregates many signatures using the secure aggregation method.
    // Performs ~ n * 256 g2 operations.
    static BLSSignature AggregateSigsSecure(
            std::vector<BLSSignature> const &sigs,
            std::vector<BLSPublicKey> const &pubKeys,
            std::vector<uint8_t*> const &messageHashes);

    // Internal methods
    static BLSSignature AggregateSigsInternal(
            std::vector<BLSSignature> const &sigs,
            std::vector<std::vector<BLSPublicKey> > const &pubKeys,
            std::vector<std::vector<uint8_t*> > const &messageHashes);

    static bool VerifyNative(
            relic::g1_t* pubKeys,
            relic::g2_t* mappedHashes,
            size_t len);

    static void CheckRelicErrors();
};

#endif  // SRC_BLS_HPP_
