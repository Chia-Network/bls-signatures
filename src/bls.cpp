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

/*
 * This implementation of verify has several steps. First, it
 * reorganizes the pubkeys and messages into groups, where
 * each group corresponds to a message. Then, it checks if the
 * siganture has info on how it was aggregated. If so, we
 * exponentiate each pk based on the exponent in the AggregationInfo.
 * If not, we find public keys that share messages with others,
 * and aggregate all of these securely (with exponents.).
 * Finally, since each public key now corresponds to a unique
 * message (since we grouped them), we can verify using the
 * distinct verification procedure.
 */
bool BLS::Verify(const BLSSignature &aggSig) {
    if (aggSig.GetAggregationInfo()->Empty()) {
        return false;
    }
    std::vector<BLSPublicKey> pubKeys = aggSig.GetAggregationInfo()
            ->GetPubKeys();
    std::vector<uint8_t*> messageHashes = aggSig.GetAggregationInfo()
            ->GetMessageHashes();
    if (pubKeys.size() != messageHashes.size()) {
        return false;
    }
    // Group all of the messages that are idential, with the
    // pubkeys and signatures, the std::maps's key is the message hash
    std::map<uint8_t*, std::vector<BLSPublicKey>,
        BLSUtil::BytesCompare32> hashToPubKeys;

    for (size_t i = 0; i < messageHashes.size(); i++) {
        auto pubKeyIter = hashToPubKeys.find(messageHashes[i]);
        if (pubKeyIter != hashToPubKeys.end()) {
            // Already one identical message, so push to vector
            pubKeyIter->second.push_back(pubKeys[i]);
        } else {
            // First time seeing this message, so create a vector
            std::vector<BLSPublicKey> newPubKey = {pubKeys[i]};
            hashToPubKeys.insert(make_pair(messageHashes[i], newPubKey));
        }
    }

    // Aggregate pubkeys of identical messages
    std::vector<BLSPublicKey> finalPubKeys;
    std::vector<uint8_t*> finalMessageHashes;
    std::vector<uint8_t*> collidingKeys;

    for (const auto &kv : hashToPubKeys) {
        relic::g1_t prod;
        g1_set_infty(prod);
        std::map<uint8_t*, size_t, BLSUtil::BytesCompare<BLSPublicKey::PUBLIC_KEY_SIZE>> dedupMap;
        for (size_t i = 0; i < kv.second.size(); i++) {
            const BLSPublicKey& pk = kv.second[i];
            uint8_t *k = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
            pk.Serialize(k);
            dedupMap.emplace(k, i);
        }

        for (const auto &kv2 : dedupMap) {
            const BLSPublicKey& pk = kv.second[kv2.second];

            relic::bn_t exponent;
            bn_new(exponent);
            try {
                aggSig.GetAggregationInfo()->GetExponent(&exponent,
                        kv.first, pk);
            } catch (std::out_of_range) {
                for (auto &p : dedupMap) {
                    delete[] p.first;
                }
                return false;
            }
            relic::g1_t tmp;
            pk.GetPoint(tmp);

            g1_mul(tmp, tmp, exponent);
            g1_add(prod, prod, tmp);
        }
        finalPubKeys.push_back(BLSPublicKey::FromG1(&prod));
        finalMessageHashes.push_back(kv.first);

        for (auto &p : dedupMap) {
            delete[] p.first;
        }
    }

    // Now we have all distinct messages, so we can verify
    relic::g1_t* pubKeysNative;
    relic::g2_t* mappedHashes;
    // Convert messages into points. Reserve the first slot in the
    // array for the signature
    mappedHashes = new relic::g2_t[finalMessageHashes.size() + 1];
    aggSig.GetPoint(mappedHashes[0]);
    for (size_t i = 0; i < finalMessageHashes.size(); i++) {
        g2_map(mappedHashes[i + 1], finalMessageHashes[i],
               BLS::MESSAGE_HASH_LEN, 0);
    }
    // Get points array from pubkey std::vector
    pubKeysNative = new relic::g1_t[finalPubKeys.size() + 1];

    // Order - 1 (which is equivalent to -1 % order)
    g1_get_gen(pubKeysNative[0]);
    relic::bn_t ordMinus1;
    relic::bn_new(ordMinus1);
    relic::g1_get_ord(ordMinus1);
    relic::bn_sub_dig(ordMinus1, ordMinus1, 1);
    relic::g1_mul(pubKeysNative[0], pubKeysNative[0], ordMinus1);
    for (size_t i = 0; i < finalPubKeys.size(); i++) {
        finalPubKeys[i].GetPoint(pubKeysNative[i + 1]);
    }
    bool result = VerifyNative(pubKeysNative, mappedHashes,
                               finalPubKeys.size() + 1);

    // Free allocated memory
    delete[] mappedHashes;
    delete[] pubKeysNative;
    for (uint8_t* k : collidingKeys) {
        delete[] k;
    }
    CheckRelicErrors();
    return result;
}

BLSPublicKey BLS::AggregatePubKeys(
        std::vector<BLSPublicKey> const &pubKeys, bool secure) {
    // bool secure = true; // Force the use of secure pubkeys
    if (pubKeys.size() < 1) {
        throw std::string("Number of public keys must be at least 1");
    }

    std::vector<uint8_t*> serPubKeys(pubKeys.size());
    for (size_t i = 0; i < pubKeys.size(); i++) {
        serPubKeys[i] = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
        pubKeys[i].Serialize(serPubKeys[i]);
    }

    // Sort the public keys by public key
    std::vector<size_t> pubKeysSorted(pubKeys.size());
    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        pubKeysSorted[i] = i;
    }

    std::sort(pubKeysSorted.begin(), pubKeysSorted.end(), [&serPubKeys](size_t a, size_t b) {
        return memcmp(serPubKeys[a], serPubKeys[b], BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
    });

    relic::bn_t* computedTs = new relic::bn_t[pubKeysSorted.size()];
    if (secure) {
        for (size_t i = 0; i < pubKeysSorted.size(); i++) {
            bn_new(computedTs[i]);
        }
        HashPubKeys(computedTs, pubKeysSorted.size(), serPubKeys, pubKeysSorted);
    }

    // Raise each key to power of each t for
    // keyComp, and multiply all together into aggKey
    relic::g1_t keyComp, aggKey;
    g1_set_infty(aggKey);

    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        const BLSPublicKey& pk = pubKeys[pubKeysSorted[i]];

        relic::g1_t pkNative;
        pk.GetPoint(pkNative);

        if (secure) {
            g1_mul(keyComp, pkNative, computedTs[i]);
        } else {
            g1_copy(keyComp, pkNative);
        }
        g1_add(aggKey, aggKey, keyComp);
    }

    delete[] computedTs;
    for (auto p : serPubKeys) {
        delete[] p;
    }

    BLSPublicKey ret = BLSPublicKey::FromG1(&aggKey);
    CheckRelicErrors();
    return ret;
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

bool BLS::VerifyNative(
        relic::g1_t* pubKeys,
        relic::g2_t* mappedHashes,
        size_t len) {
    relic::gt_t target, candidate;

    // Target = 1
    relic::fp12_zero(target);
    relic::fp_set_dig(target[0][0][0], 1);

    // prod e(pubkey[i], hash[i]) * e(-1 * g1, aggSig)
    // Performs pubKeys.size() pairings
    pc_map_sim(candidate, pubKeys, mappedHashes, len);

    // 1 =? prod e(pubkey[i], hash[i]) * e(g1, aggSig)
    if (relic::fp12_cmp(target, candidate) != CMP_EQ ||
            relic::core_get()->code != STS_OK) {
        relic::core_get()->code = STS_OK;
        return false;
    }
    CheckRelicErrors();
    return true;
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
