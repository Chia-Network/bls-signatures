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
#if BLSALLOC == sodium
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
#if BLSALLOC == sodium
    if (libsodium::sodium_init() < 0) {
        throw std::string("Libsodium initialization failed.");
    }
#endif
}

void BLS::Clean() {
    relic::core_clean();
}

BLSSignature BLS::AggregateSigsSimple(std::vector<BLSSignature> const &sigs) {
    if (sigs.size() < 1) {
        throw std::string("Must have atleast one signatures and key");
    }
    if (sigs.size() == 1) {
        return sigs[0];
    }
    relic::g2_t aggSig, tempSig;
    g2_set_infty(aggSig);

    // Multiplies the signatures together (relic uses additive group operation)
    for (const BLSSignature &sig : sigs) {
        sig.GetPoint(tempSig);
        g2_add(aggSig, aggSig, tempSig);
    }
    BLSSignature ret = BLSSignature::FromG2(&aggSig);
    CheckRelicErrors();
    return ret;
}

BLSSignature BLS::AggregateSigsSecure(
        std::vector<BLSSignature> const &sigs,
        std::vector<BLSPublicKey> const &pubKeys,
        std::vector<uint8_t*> const &messageHashes) {
    if (sigs.size() != pubKeys.size() || sigs.size() != messageHashes.size()
        || sigs.size() < 1) {
        throw std::string("Must have atleast one signature, key, and message");
    }

    // Sort the public keys and signature by message + public key
    std::map<const uint8_t*, const BLSSignature> sigsMap;
    std::map<const uint8_t*, const BLSPublicKey> pkMap;
    std::vector<uint8_t*> sortKeysSorted;
    for (size_t i = 0; i < pubKeys.size(); i++) {
        uint8_t* sortKey = new uint8_t[MESSAGE_HASH_LEN
                                       + BLSPublicKey::PUBLIC_KEY_SIZE];
        std::memcpy(sortKey, messageHashes[i], MESSAGE_HASH_LEN);
        pubKeys[i].Serialize(sortKey + BLS::MESSAGE_HASH_LEN);
        sigsMap.insert(std::make_pair(sortKey, sigs[i]));
        pkMap.insert(std::make_pair(sortKey, pubKeys[i]));
        sortKeysSorted.push_back(sortKey);
    }
    sort(begin(sortKeysSorted), end(sortKeysSorted), BLSUtil::BytesCompare80());
    std::vector<BLSSignature> sigsSorted;
    std::vector<BLSPublicKey> pubKeysSorted;

    for (const uint8_t* k : sortKeysSorted) {
        sigsSorted.push_back(sigsMap.at(k));
        pubKeysSorted.push_back(pkMap.at(k));
    }

    relic::bn_t* computedTs = new relic::bn_t[sortKeysSorted.size()];
    for (size_t i = 0; i < sortKeysSorted.size(); i++) {
        relic::bn_new(computedTs[i]);
    }
    HashPubKeys(computedTs, pubKeysSorted.size(), pubKeysSorted);

    // Copy each signature into sig, raise to power of each t for
    // sigComp, and multiply all together into aggSig
    relic::g2_t sig, sigComp, aggSig;
    g2_set_infty(aggSig);

    for (size_t i = 0; i < sortKeysSorted.size(); i++) {
        sigsSorted[i].GetPoint(sig);
        g2_mul(sigComp, sig, computedTs[i]);
        g2_add(aggSig, aggSig, sigComp);
    }
    delete[] computedTs;

    BLSSignature ret = BLSSignature::FromG2(&aggSig);
    CheckRelicErrors();
    return ret;
}

BLSSignature BLS::AggregateSigs(
        std::vector<BLSSignature> const &sigs) {
    BLS::AssertInitialized();
    std::vector<std::vector<BLSPublicKey> > pubKeys;
    std::vector<std::vector<uint8_t*> > messageHashes;

    // Extracts the public keys and messages from the aggregation info
    for (const BLSSignature &sig : sigs) {
        const AggregationInfo &info = *sig.GetAggregationInfo();
        if (info.Empty()) {
            throw std::string("Signature must include aggregation info.");
        }
        std::vector<BLSPublicKey> infoPubKeys = info.GetPubKeys();
        std::vector<uint8_t*> infoMessageHashes = info.GetMessageHashes();
        if (infoPubKeys.size() < 1 || infoMessageHashes.size() < 1) {
            throw std::string("AggregationInfo must have items");
        }
        pubKeys.push_back(infoPubKeys);
        std::vector<uint8_t*> currMessageHashes;
        for (const uint8_t* infoMessageHash : infoMessageHashes) {
            uint8_t* messageHash = new uint8_t[BLS::MESSAGE_HASH_LEN];
            std::memcpy(messageHash, infoMessageHash, BLS::MESSAGE_HASH_LEN);
            currMessageHashes.push_back(messageHash);
        }
        messageHashes.push_back(currMessageHashes);
    }

    if (sigs.size() != pubKeys.size()
        || pubKeys.size() != messageHashes.size()) {
        throw std::string("Lengths of vectors must match.");
    }
    for (size_t i = 0; i < messageHashes.size(); i++) {
        if (pubKeys[i].size() != messageHashes[i].size()) {
            throw std::string("Lengths of vectors must match.");
        }
    }
    BLSSignature ret = AggregateSigsInternal(sigs, pubKeys,
                                             messageHashes);
    for (std::vector<uint8_t*> group : messageHashes) {
        for (const uint8_t* messageHash : group) {
            delete[] messageHash;
        }
    }
    return ret;
}

BLSSignature BLS::AggregateSigsInternal(
        std::vector<BLSSignature> const &sigs,
        std::vector<std::vector<BLSPublicKey> > const &pubKeys,
        std::vector<std::vector<uint8_t*> > const &messageHashes) {
    BLS::AssertInitialized();
    if (sigs.size() != pubKeys.size()
        || pubKeys.size() != messageHashes.size()) {
        throw std::string("Lengths of std::vectors must match.");
    }
    for (size_t i = 0; i < messageHashes.size(); i++) {
        if (pubKeys[i].size() != messageHashes[i].size()) {
            throw std::string("Lengths of std::vectors must match.");
        }
    }

    // Find colliding vectors, save colliding messages
    std::set<const uint8_t*, BLSUtil::BytesCompare32> messagesSet;
    std::set<const uint8_t*, BLSUtil::BytesCompare32> collidingMessagesSet;
    for (auto &msgVector : messageHashes) {
        std::set<const uint8_t*, BLSUtil::BytesCompare32> messagesSetLocal;
        for (auto &msg : msgVector) {
            auto lookupEntry = messagesSet.find(msg);
            auto lookupEntryLocal = messagesSetLocal.find(msg);
            if (lookupEntryLocal == messagesSetLocal.end() &&
                        lookupEntry != messagesSet.end()) {
                collidingMessagesSet.insert(msg);
            }
            messagesSet.insert(msg);
            messagesSetLocal.insert(msg);
        }
    }
    if (collidingMessagesSet.empty()) {
        // There are no colliding messages between the groups, so we
        // will just aggregate them all simply. Note that we assume
        // that every group is a valid aggregate signature. If an invalid
        // or insecure signature is given, and invalid signature will
        // be created. We don't verify for performance reasons.
        BLSSignature ret = AggregateSigsSimple(sigs);
        std::vector<AggregationInfo> infos;
        for (const BLSSignature &sig : sigs) {
            infos.push_back(*sig.GetAggregationInfo());
        }
        ret.SetAggregationInfo(AggregationInfo::MergeInfos(infos));
        return ret;
    }

    // There are groups that share messages, therefore we need
    // to use a secure form of aggregation. First we find which
    // groups collide, and securely aggregate these. Then, we
    // use simple aggregation at the end.
    std::vector<BLSSignature > collidingSigs;
    std::vector<BLSSignature> nonCollidingSigs;
    std::vector<std::vector<uint8_t*> > collidingMessageHashes;
    std::vector<std::vector<BLSPublicKey> > collidingPks;

    for (size_t i = 0; i < sigs.size(); i++) {
        bool groupCollides = false;
        for (const uint8_t* msg : messageHashes[i]) {
            auto lookupEntry = collidingMessagesSet.find(msg);
            if (lookupEntry != collidingMessagesSet.end()) {
                groupCollides = true;
                collidingSigs.push_back(sigs[i]);
                collidingMessageHashes.push_back(messageHashes[i]);
                collidingPks.push_back(pubKeys[i]);
                break;
            }
        }
        if (!groupCollides) {
            nonCollidingSigs.push_back(sigs[i]);
        }
    }

    // Sort signatures by aggInfo
    std::vector<BLSSignature> sigsSorted;
    for (const BLSSignature &sig : collidingSigs) {
        sigsSorted.push_back(sig);
    }
    std::sort(begin(sigsSorted), end(sigsSorted),
                [](const BLSSignature &a, const BLSSignature &b) -> bool {
        return *a.GetAggregationInfo() < *b.GetAggregationInfo();
    });
    std::vector<uint8_t*> sortKeysSorted;
    for (size_t i = 0; i < collidingPks.size(); i++) {
        for (size_t j = 0; j < collidingPks[i].size(); j++) {
            uint8_t* sortKey = new uint8_t[MESSAGE_HASH_LEN
                                        + BLSPublicKey::PUBLIC_KEY_SIZE];
            std::memcpy(sortKey, collidingMessageHashes[i][j], MESSAGE_HASH_LEN);
            collidingPks[i][j].Serialize(sortKey + BLS::MESSAGE_HASH_LEN);
            sortKeysSorted.push_back(sortKey);
        }
    }
    // Sort everything according to message || pubkey
    sort(begin(sortKeysSorted), end(sortKeysSorted),
            BLSUtil::BytesCompare80());

    std::vector<BLSPublicKey> pubKeysSorted;
    for (const uint8_t* sortKey : sortKeysSorted) {
        pubKeysSorted.push_back(BLSPublicKey::FromBytes(sortKey
                + BLS::MESSAGE_HASH_LEN));
    }
    relic::bn_t* computedTs = new relic::bn_t[sigsSorted.size()];
    for (size_t i = 0; i < sigsSorted.size(); i++) {
        bn_new(computedTs[i]);
    }
    HashPubKeys(computedTs, sigsSorted.size(), pubKeysSorted);

    // Copy each signature into sig, raise to power of each t for
    // sigComp, and multiply all together into aggSig
    relic::g2_t sig, sigComp, aggSig;
    g2_set_infty(aggSig);
    std::vector<AggregationInfo> infos;

    // Also accumulates aggregation info for each signature
    for (size_t i = 0; i < sigsSorted.size(); i++) {
        sigsSorted[i].GetPoint(sig);
        g2_mul(sigComp, sig, computedTs[i]);
        g2_add(aggSig, aggSig, sigComp);
        infos.push_back(*sigsSorted[i].GetAggregationInfo());
    }

    for (const BLSSignature &nonColliding : nonCollidingSigs) {
        nonColliding.GetPoint(sig);
        g2_add(aggSig, aggSig, sig);
        infos.push_back(*nonColliding.GetAggregationInfo());
    }
    BLSSignature ret = BLSSignature::FromG2(&aggSig);

    // Merge the aggregation infos, which will be combined in an
    // identical way as above.
    ret.SetAggregationInfo(AggregationInfo::MergeInfos(infos));

    delete[] computedTs;
    for (const uint8_t* sortKey : sortKeysSorted) {
        delete[] sortKey;
    }
    return ret;
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
        std::set<BLSPublicKey> dedupSet;
        for (BLSPublicKey pk : kv.second) dedupSet.insert(pk);
        std::vector<BLSPublicKey> dedup;
        dedup.assign(begin(dedupSet), end(dedupSet));

        for (const BLSPublicKey &pk : dedup) {
            relic::bn_t exponent;
            bn_new(exponent);
            try {
                aggSig.GetAggregationInfo()->GetExponent(&exponent,
                        kv.first, pk);
            } catch (std::out_of_range) {
                return false;
            }
            relic::g1_t tmp;
            pk.GetPoint(tmp);

            g1_mul(tmp, tmp, exponent);
            g1_add(prod, prod, tmp);
        }
        finalPubKeys.push_back(BLSPublicKey::FromG1(&prod));
        finalMessageHashes.push_back(kv.first);
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

    // Sort the public keys by public key
    std::vector<BLSPublicKey> pubKeysSorted;
    for (BLSPublicKey pk : pubKeys) {
        pubKeysSorted.push_back(pk);
    }
    sort(begin(pubKeysSorted), end(pubKeysSorted));

    relic::bn_t* computedTs = new relic::bn_t[pubKeysSorted.size()];
    if (secure) {
        for (size_t i = 0; i < pubKeysSorted.size(); i++) {
            bn_new(computedTs[i]);
        }
        HashPubKeys(computedTs, pubKeysSorted.size(), pubKeysSorted);
    }

    relic::g1_t * pubKeysNative = new relic::g1_t[pubKeysSorted.size()];
    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        pubKeysSorted[i].GetPoint(pubKeysNative[i]);
    }

    // Raise each key to power of each t for
    // keyComp, and multiply all together into aggKey
    relic::g1_t keyComp, aggKey;
    g1_set_infty(aggKey);

    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        if (secure) {
            g1_mul(keyComp, pubKeysNative[i], computedTs[i]);
        } else {
            g1_copy(keyComp, pubKeysNative[i]);
        }
        g1_add(aggKey, aggKey, keyComp);
    }

    delete[] pubKeysNative;
    delete[] computedTs;
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

    // Sort the public keys and private keys by public key
    std::map<const BLSPublicKey, const BLSPrivateKey> privateKeysMap;
    for (size_t i = 0; i < pubKeys.size(); i++) {
        privateKeysMap.insert(std::make_pair(pubKeys[i], privateKeys[i]));
    }
    std::vector<BLSPublicKey> pubKeysSorted;
    std::vector<BLSPrivateKey> privateKeysSorted;
    for (BLSPublicKey pk : pubKeys) {
        pubKeysSorted.push_back(pk);
    }
    sort(begin(pubKeysSorted), end(pubKeysSorted));
    for (BLSPublicKey pk : pubKeysSorted) {
        privateKeysSorted.push_back(privateKeysMap.at(pk));
    }

    relic::bn_t order;
    bn_new(order);

    // Use secure allocation to store temporary sk variables
    relic::bn_t* workingMemory = BLSUtil::SecAlloc<relic::bn_t>(3);
    bn_new(workingMemory[0]);
    bn_new(workingMemory[1]);
    bn_new(workingMemory[2]);

    g2_get_ord(order);

    relic::bn_t* computedTs = new relic::bn_t[pubKeysSorted.size()];
    if (secure) {
        for (size_t i = 0; i < pubKeysSorted.size(); i++) {
            bn_new(computedTs[i]);
        }
        HashPubKeys(computedTs, pubKeysSorted.size(), pubKeysSorted);
    }

    bn_zero(workingMemory[2]);
    for (size_t i = 0; i < privateKeysSorted.size(); i++) {
        *workingMemory[0] = **privateKeysSorted[i].GetValue();
        if (secure) {
            bn_mul_comba(workingMemory[1], workingMemory[0], computedTs[i]);
        } else {
            bn_copy(workingMemory[1], workingMemory[0]);
        }
        bn_add(workingMemory[2], workingMemory[2], workingMemory[1]);
        bn_mod_basic(workingMemory[2], workingMemory[2], order);
    }
    delete[] computedTs;

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
    for (size_t i = 0; len != 0 && i < len - 1; i++) {
        if (g2_cmp(mappedHashes[i], mappedHashes[i+1]) == CMP_EQ) {
            return false;
        }
    }
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
                      std::vector<BLSPublicKey> const &pubKeys) {
    uint8_t *pkBuffer = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE
                                    * (pubKeys.size())];
    relic::bn_t order;

    for (size_t i = 0; i < pubKeys.size(); i++) {
        pubKeys[i].Serialize(pkBuffer +
                             i * BLSPublicKey::PUBLIC_KEY_SIZE);
    }

    bn_new(order);
    g2_get_ord(order);

    uint8_t pkHash[32];
    BLSUtil::Hash256(pkHash, pkBuffer,
                     BLSPublicKey::PUBLIC_KEY_SIZE * pubKeys.size());
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
