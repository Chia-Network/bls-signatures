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

#include <chrono>
#include "bls.hpp"
#include "test-utils.hpp"

extern "C" {
#include "relic.h"
}

using std::string;
using std::vector;
using std::cout;
using std::endl;

using namespace bls;


void benchSigs() {
    string testName = "Sigining";
    double numIters = 5000;
    PrivateKey sk = AugSchemeMPL::KeyGen(getRandomSeed());
    vector<uint8_t> message1 = sk.GetG1Element().Serialize();

    auto start = startStopwatch();

    for (size_t i = 0; i < numIters; i++) {
        AugSchemeMPL::Sign(sk, message1);
    }
    endStopwatch(testName, start, numIters);
}

void benchVerification() {
    string testName = "Verification";
    double numIters = 10000;
    PrivateKey sk = AugSchemeMPL::KeyGen(getRandomSeed());
    G1Element pk = sk.GetG1Element();

    std::vector<G2Element> sigs;

    for (size_t i = 0; i < numIters; i++) {
        uint8_t message[4];
        Util::IntToFourBytes(message, i);
        vector<uint8_t> messageBytes(message, message + 4);
        sigs.push_back(AugSchemeMPL::Sign(sk, messageBytes));
    }

    auto start = startStopwatch();
    for (size_t i = 0; i < numIters; i++) {
        uint8_t message[4];
        Util::IntToFourBytes(message, i);
        vector<uint8_t> messageBytes(message, message + 4);
        bool ok = AugSchemeMPL::Verify(pk, messageBytes, sigs[i]);
        ASSERT(ok);
    }
    endStopwatch(testName, start, numIters);
}

void benchBatchVerification() {
    double numIters = 100000;

    vector<G2Element> sigs;
    vector<G1Element> pks;
    vector<vector<uint8_t>> ms;

    for (size_t i = 0; i < numIters; i++) {
        uint8_t message[4];
        Util::IntToFourBytes(message, i);
        vector<uint8_t> messageBytes(message, message + 4);
        PrivateKey sk = AugSchemeMPL::KeyGen(getRandomSeed());
        G1Element pk = sk.GetG1Element();
        sigs.push_back(AugSchemeMPL::Sign(sk, messageBytes));
        pks.push_back(pk);
        ms.push_back(messageBytes);
    }

    auto start = startStopwatch();
    G2Element aggSig = AugSchemeMPL::Aggregate(sigs);
    endStopwatch("Aggregation", start, numIters);

    start = startStopwatch();
    bool ok = AugSchemeMPL::AggregateVerify(pks, ms, aggSig);
    ASSERT(ok);
    endStopwatch("Batch verification", start, numIters);
}

void benchFastAggregateVerification() {
    double numIters = 5000;

    vector<G2Element> sigs;
    vector<G1Element> pks;
    vector<uint8_t> message = {1, 2, 3, 4, 5, 6, 7, 8};
    vector<G2Element> pops;

    for (size_t i = 0; i < numIters; i++) {
        PrivateKey sk = PopSchemeMPL::KeyGen(getRandomSeed());
        G1Element pk = sk.GetG1Element();
        sigs.push_back(PopSchemeMPL::Sign(sk, message));
        pops.push_back(PopSchemeMPL::PopProve(sk));
        pks.push_back(pk);
    }

    auto start = startStopwatch();
    G2Element aggSig = PopSchemeMPL::Aggregate(sigs);
    endStopwatch("PopScheme Aggregation", start, numIters);


    start = startStopwatch();
    for (size_t i = 0; i < numIters; i++) {
        bool ok = PopSchemeMPL::PopVerify(pks[i], pops[i]);
        ASSERT(ok);
    }
    endStopwatch("PopScheme Proofs verification", start, numIters);

    start = startStopwatch();
    bool ok = PopSchemeMPL::FastAggregateVerify(pks, message, aggSig);
    ASSERT(ok);
    endStopwatch("PopScheme verification", start, numIters);
}

int main(int argc, char* argv[]) {
    benchSigs();
    benchVerification();
    benchBatchVerification();
    benchFastAggregateVerification();
}
