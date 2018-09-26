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

#include <set>
#include <string>
#include <cstring>
#include <algorithm>

#include "bls.hpp"

const char BLS::GROUP_ORDER[] =
        "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";

bool BLSInitResult = BLS::Init();

bool BLS::Init() {
    if (ALLOC != AUTO) {
        std::cout << "Must have ALLOC == AUTO";
        return false;
    }
    relic::core_init();
    if (relic::err_get_code() != STS_OK) {
        std::cout << "core_init() failed";
        return false;
    }

    const int r = relic::ep_param_set_any_pairf();
    if (r != STS_OK) {
        std::cout << "ep_param_set_any_pairf() failed";
        return false;
    }
#if BLSALLOC_SODIUM
    if (libsodium::sodium_init() < 0) {
        std::cout << "libsodium init failed";
        return false;
    }
#endif
    return true;
}

void BLS::AssertInitialized() {
    if (!relic::core_get()) {
        throw std::string("Library not initialized properly. Call BLS::Init()");
    }
#if BLSALLOC_SODIUM
    if (libsodium::sodium_init() < 0) {
        throw std::string("Libsodium initialization failed.");
    }
#endif
}

void BLS::Clean() {
    relic::core_clean();
}

BLSPrivateKey BLS::AggregatePrivKeys(
        std::vector<BLSPrivateKey> const &privateKeys,
        std::vector<BLSPublicKey> const &pubKeys,
        bool secure) {
    if (secure && pubKeys.size() != privateKeys.size()) {
        throw std::string("Number of public keys must equal number of private keys");
    }

    std::vector<uint8_t*> serPubKeys(pubKeys.size());
    for (size_t i = 0; i < pubKeys.size(); i++) {
        serPubKeys[i] = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
        pubKeys[i].Serialize(serPubKeys[i]);
    }

    // Sort the public keys and private keys by public key
    std::vector<size_t> keysSorted(privateKeys.size());
    for (size_t i = 0; i < privateKeys.size(); i++) {
        keysSorted[i] = i;
    }

    if (secure) {
        std::sort(keysSorted.begin(), keysSorted.end(), [&serPubKeys](size_t a, size_t b) {
            return memcmp(serPubKeys[a], serPubKeys[b], BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
        });
    }

    relic::bn_t order;
    bn_new(order);

    // Use secure allocation to store temporary sk variables
    relic::bn_t* workingMemory = BLSUtil::SecAlloc<relic::bn_t>(3);
    bn_new(workingMemory[0]);
    bn_new(workingMemory[1]);
    bn_new(workingMemory[2]);

    g2_get_ord(order);

    relic::bn_t* computedTs = new relic::bn_t[keysSorted.size()];
    if (secure) {
        for (size_t i = 0; i < keysSorted.size(); i++) {
            bn_new(computedTs[i]);
        }
        HashPubKeys(computedTs, keysSorted.size(), serPubKeys, keysSorted);
    }

    bn_zero(workingMemory[2]);
    for (size_t i = 0; i < keysSorted.size(); i++) {
        *workingMemory[0] = **privateKeys[keysSorted[i]].GetValue();
        if (secure) {
            bn_mul_comba(workingMemory[1], workingMemory[0], computedTs[i]);
        } else {
            bn_copy(workingMemory[1], workingMemory[0]);
        }
        bn_add(workingMemory[2], workingMemory[2], workingMemory[1]);
        bn_mod_basic(workingMemory[2], workingMemory[2], order);
    }
    delete[] computedTs;
    for (auto p : serPubKeys) {
        delete[] p;
    }

    uint8_t* privateKeyBytes =
            BLSUtil::SecAlloc<uint8_t>(BLSPrivateKey::PRIVATE_KEY_SIZE);
    bn_write_bin(privateKeyBytes,
                 BLSPrivateKey::PRIVATE_KEY_SIZE,
                 workingMemory[2]);
    BLSUtil::SecFree(workingMemory);

    BLSPrivateKey ret = BLSPrivateKey::FromBytes(privateKeyBytes);

    BLSUtil::SecFree(privateKeyBytes);
    CheckRelicErrors();
    return ret;
}

void BLS::HashPubKeys(relic::bn_t* output, size_t numOutputs,
                      std::vector<uint8_t*> const &serPubKeys,
                      std::vector<size_t> const& sortedIndices) {
    relic::bn_t order;

    bn_new(order);
    g2_get_ord(order);

    uint8_t *pkBuffer = new uint8_t[serPubKeys.size() * BLSPublicKey::PUBLIC_KEY_SIZE];

    for (size_t i = 0; i < serPubKeys.size(); i++) {
        memcpy(pkBuffer + i * BLSPublicKey::PUBLIC_KEY_SIZE, serPubKeys[sortedIndices[i]], BLSPublicKey::PUBLIC_KEY_SIZE);
    }

    uint8_t pkHash[32];
    BLSUtil::Hash256(pkHash, pkBuffer, serPubKeys.size() * BLSPublicKey::PUBLIC_KEY_SIZE);
    for (size_t i = 0; i < numOutputs; i++) {
        uint8_t hash[32];
        uint8_t buffer[4 + 32];
        memset(buffer, 0, 4);
        // Set first 4 bytes to index, to generate different ts
        BLSUtil::IntToFourBytes(buffer, i);
        // Set next 32 bytes as the hash of all the public keys
        std::memcpy(buffer + 4, pkHash, 32);
        BLSUtil::Hash256(hash, buffer, 4 + 32);

        bn_read_bin(output[i], hash, 32);
        bn_mod_basic(output[i], output[i], order);
    }

    delete[] pkBuffer;

    CheckRelicErrors();
}

void BLS::CheckRelicErrors() {
    if (!relic::core_get()) {
        throw std::string("Library not initialized properly. Call BLS::Init()");
    }
    if (relic::core_get()->code != STS_OK) {
        throw std::string("Relic library error");
    }
}
