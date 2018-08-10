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

#include <chrono>
#include "bls.hpp"
#include "test-utils.hpp"

using std::string;
using std::vector;
using std::cout;
using std::endl;

void benchSigs() {
    string testName = "Sigining";
    double numIters = 1000;
    uint8_t seed[32];
    getRandomSeed(seed);
    BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
    BLSPublicKey pk = sk.GetPublicKey();
    uint8_t message1[48];
    pk.Serialize(message1);

    auto start = startStopwatch();

    for (size_t i = 0; i < numIters; i++) {
        sk.Sign(message1, sizeof(message1));
    }
    endStopwatch(testName, start, numIters);
}

void benchVerification() {
    string testName = "Verification";
    double numIters = 1000;
    uint8_t seed[32];
    getRandomSeed(seed);
    BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);

    std::vector<BLSSignature> sigs;

    for (size_t i = 0; i < numIters; i++) {
        uint8_t message[4];
        BLSUtil::IntToFourBytes(message, i);
        sigs.push_back(sk.Sign(message, 4));
    }

    auto start = startStopwatch();
    for (size_t i = 0; i < numIters; i++) {
        uint8_t message[4];
        BLSUtil::IntToFourBytes(message, i);
        bool ok = BLS::Verify(sigs[i]);
        ASSERT(ok);
    }
    endStopwatch(testName, start, numIters);
}

void benchAggregateSigsSecure() {
    uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
    double numIters = 1000;

    std::vector<BLSPrivateKey> sks;
    std::vector<BLSPublicKey> pks;
    std::vector<BLSSignature> sigs;

    for (int i = 0; i < numIters; i++) {
        uint8_t seed[32];
        getRandomSeed(seed);

        BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
        const BLSPublicKey pk = sk.GetPublicKey();
        sks.push_back(sk);
        pks.push_back(pk);
        sigs.push_back(sk.Sign(message1, sizeof(message1)));
    }

    auto start = startStopwatch();
    BLSSignature aggSig = BLS::AggregateSigs(sigs);
    endStopwatch("Generate aggregate signature, same message",
                 start, numIters);

    auto start2 = startStopwatch();
    const BLSPublicKey aggPubKey = BLS::AggregatePubKeys(pks, true);
    endStopwatch("Generate aggregate pk, same message", start2, numIters);

    auto start3 = startStopwatch();
    aggSig.SetAggregationInfo(AggregationInfo::FromMsg(
            aggPubKey, message1, sizeof(message1)));
    ASSERT(BLS::Verify(aggSig));
    endStopwatch("Verify agg signature, same message", start3, numIters);
}

void benchBatchVerification() {
    string testName = "Batch verification";
    double numIters = 1000;

    std::vector<BLSSignature> sigs;
    std::vector<BLSSignature> cache;
    for (size_t i = 0; i < numIters; i++) {
        uint8_t seed[32];
        getRandomSeed(seed);

        BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
        uint8_t *message = new uint8_t[32];
        getRandomSeed(message);
        sigs.push_back(sk.Sign(message, 1 + (i % 5)));
        // Small message, so some messages are the same
        if (message[0] < 225) {  // Simulate having ~90% cached transactions
            BLS::Verify(sigs.back());
            cache.push_back(sigs.back());
        }
    }

    BLSSignature aggregate = BLS::AggregateSigs(sigs);

    auto start = startStopwatch();
    ASSERT(BLS::Verify(aggregate));
    endStopwatch(testName, start, numIters);


    start = startStopwatch();
    const BLSSignature aggSmall = aggregate.DivideBy(cache);
    ASSERT(BLS::Verify(aggSmall));
    endStopwatch(testName + " with cached verifications", start, numIters);
}

void benchAggregateSigsSimple() {
    double numIters = 1000;
    std::vector<BLSPrivateKey> sks;
    std::vector<BLSSignature> sigs;

    for (int i = 0; i < numIters; i++) {
        uint8_t* message = new uint8_t[48];
        uint8_t seed[32];
        getRandomSeed(seed);

        BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
        const BLSPublicKey pk = sk.GetPublicKey();
        pk.Serialize(message);
        sks.push_back(sk);
        sigs.push_back(sk.Sign(message, sizeof(message)));
    }

    auto start = startStopwatch();
    BLSSignature aggSig = BLS::AggregateSigs(sigs);
    endStopwatch("Generate aggregate signature, distinct messages",
                 start, numIters);

    auto start2 = startStopwatch();
    ASSERT(BLS::Verify(aggSig));
    endStopwatch("Verify aggregate signature, distinct messages",
                 start2, numIters);
}

void benchDegenerateTree() {
    double numIters = 30;
    uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
    uint8_t seed[32];
    getRandomSeed(seed);
    BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
    BLSSignature aggSig = sk1.Sign(message1, sizeof(message1));

    auto start = startStopwatch();
    for (size_t i = 0; i < numIters; i++) {
        getRandomSeed(seed);
        BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
        BLSSignature sig = sk.Sign(message1, sizeof(message1));
        std::vector<BLSSignature> sigs = {aggSig, sig};
        aggSig = BLS::AggregateSigs(sigs);
    }
    endStopwatch("Generate degenerate aggSig tree",
                 start, numIters);

    start = startStopwatch();
    ASSERT(BLS::Verify(aggSig));
    endStopwatch("Verify degenerate aggSig tree",
                 start, numIters);
}

int main(int argc, char* argv[]) {
    benchSigs();
    benchVerification();
    benchBatchVerification();
    benchAggregateSigsSecure();
    benchAggregateSigsSimple();
    benchDegenerateTree();
}
