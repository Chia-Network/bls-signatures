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

#include <string>
#include <cstring>
#include <set>
#include <algorithm>

#include "blssignature.hpp"
#include "bls.hpp"

using std::string;
using relic::bn_t;
using relic::fp_t;

BLSInsecureSignature BLSInsecureSignature::FromBytes(const uint8_t *data) {
    BLS::AssertInitialized();
    BLSInsecureSignature sigObj = BLSInsecureSignature();
    uint8_t uncompressed[SIGNATURE_SIZE + 1];
    std::memcpy(uncompressed + 1, data, SIGNATURE_SIZE);
    if (data[0] & 0x80) {
        uncompressed[0] = 0x03;   // Insert extra byte for Y=1
        uncompressed[1] &= 0x7f;  // Remove initial Y bit
    } else {
        uncompressed[0] = 0x02;   // Insert extra byte for Y=0
    }
    relic::g2_read_bin(sigObj.sig, uncompressed, SIGNATURE_SIZE + 1);
    return sigObj;
}

BLSInsecureSignature BLSInsecureSignature::FromG2(const relic::g2_t* element) {
    BLS::AssertInitialized();
    BLSInsecureSignature sigObj = BLSInsecureSignature();
    relic::g2_copy(sigObj.sig, *(relic::g2_t*)element);
    return sigObj;
}

BLSInsecureSignature::BLSInsecureSignature() {
    BLS::AssertInitialized();
    g2_set_infty(sig);
}

BLSInsecureSignature::BLSInsecureSignature(const BLSInsecureSignature &signature) {
    BLS::AssertInitialized();
    g2_copy(sig, *(relic::g2_t*)&signature.sig);
}

void BLSInsecureSignature::GetPoint(relic::ep2_st* output) const {
    *output = *sig;
}

BLSInsecureSignature BLSInsecureSignature::Aggregate(const BLSInsecureSignature& r) const {
    BLSInsecureSignature result(*this);
    g2_add(result.sig, *(relic::g2_t*)&result.sig, *(relic::g2_t*)&r.sig);
    return result;
}

BLSInsecureSignature BLSInsecureSignature::Aggregate(const std::vector<BLSInsecureSignature>& sigs) {
    if (sigs.empty()) {
        throw std::string("sigs must not be empty");
    }
    BLSInsecureSignature result = sigs[0];
    for (size_t i = 1; i < sigs.size(); i++) {
        g2_add(result.sig, result.sig, *(relic::g2_t*)&sigs[i].sig);
    }
    return result;
}

BLSInsecureSignature BLSInsecureSignature::DivideBy(const BLSInsecureSignature& r) const {
    BLSInsecureSignature result(*this);
    g2_sub(result.sig, *(relic::g2_t*)&result.sig, *(relic::g2_t*)&r.sig);
    return result;
}

BLSInsecureSignature BLSInsecureSignature::Mul(const relic::bn_t n) const {
    BLSInsecureSignature result(*this);
    g2_mul(result.sig, result.sig, n);
    return result;
}

void BLSInsecureSignature::Serialize(uint8_t* buffer) const {
    BLS::AssertInitialized();
    CompressPoint(buffer, &sig);
}

std::vector<uint8_t> BLSInsecureSignature::Serialize() const {
    std::vector<uint8_t> data(SIGNATURE_SIZE);
    Serialize(data.data());
    return data;
}

bool operator==(BLSInsecureSignature const &a, BLSInsecureSignature const &b) {
    BLS::AssertInitialized();
    return g2_cmp(*(relic::g2_t*)&a.sig, *(relic::g2_t*)b.sig) == CMP_EQ;
}

bool operator!=(BLSInsecureSignature const &a, BLSInsecureSignature const &b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, BLSInsecureSignature const &s) {
    BLS::AssertInitialized();
    uint8_t data[BLSInsecureSignature::SIGNATURE_SIZE];
    s.Serialize(data);
    return os << BLSUtil::HexStr(data, BLSInsecureSignature::SIGNATURE_SIZE);
}

BLSInsecureSignature& BLSInsecureSignature::operator=(const BLSInsecureSignature &rhs) {
    BLS::AssertInitialized();
    relic::g2_copy(sig, *(relic::g2_t*)&rhs.sig);
    return *this;
}

void BLSInsecureSignature::CompressPoint(uint8_t* result, const relic::g2_t* point) {
    uint8_t buffer[BLSInsecureSignature::SIGNATURE_SIZE + 1];
    g2_write_bin(buffer, BLSInsecureSignature::SIGNATURE_SIZE + 1, *(relic::g2_t*)point, 1);

    if (buffer[0] == 0x03) {
        buffer[1] |= 0x80;
    }
    std::memcpy(result, buffer + 1, SIGNATURE_SIZE);
}

///

BLSSignature BLSSignature::FromBytes(const uint8_t* data) {
    BLSSignature result;
    result.sig = BLSInsecureSignature::FromBytes(data);
    return result;
}

BLSSignature BLSSignature::FromBytes(const uint8_t *data, const AggregationInfo &info) {
    BLSSignature ret = FromBytes(data);
    ret.SetAggregationInfo(info);
    return ret;
}

BLSSignature BLSSignature::FromG2(const relic::g2_t* element) {
    BLSSignature result;
    result.sig = BLSInsecureSignature::FromG2(element);
    return result;
}

BLSSignature BLSSignature::FromG2(const relic::g2_t* element, const AggregationInfo& info) {
    BLSSignature ret = FromG2(element);
    ret.SetAggregationInfo(info);
    return ret;
}

BLSSignature BLSSignature::FromInsecureSig(const BLSInsecureSignature& sig) {
    return FromG2(&sig.sig);
}

BLSSignature BLSSignature::FromInsecureSig(const BLSInsecureSignature& sig, const AggregationInfo& info) {
    return FromG2(&sig.sig, info);
}

BLSSignature::BLSSignature(const BLSSignature &_signature)
    : sig(_signature.sig),
      aggregationInfo(_signature.aggregationInfo) {
}

void BLSSignature::GetPoint(relic::ep2_st* output) const {
    sig.GetPoint(output);
}

const AggregationInfo* BLSSignature::GetAggregationInfo() const {
    return &aggregationInfo;
}

void BLSSignature::SetAggregationInfo(
        const AggregationInfo &newAggregationInfo) {
    aggregationInfo = newAggregationInfo;
}

void BLSSignature::Serialize(uint8_t* buffer) const {
    sig.Serialize(buffer);
}

std::vector<uint8_t> BLSSignature::Serialize() const {
    return sig.Serialize();
}

bool operator==(BLSSignature const &a, BLSSignature const &b) {
    BLS::AssertInitialized();
    return a.sig == b.sig;
}

bool operator!=(BLSSignature const &a, BLSSignature const &b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, BLSSignature const &s) {
    BLS::AssertInitialized();
    uint8_t data[BLSInsecureSignature::SIGNATURE_SIZE];
    s.Serialize(data);
    return os << BLSUtil::HexStr(data, BLSInsecureSignature::SIGNATURE_SIZE);
}

BLSSignature BLSSignature::AggregateSigs(
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

BLSSignature BLSSignature::AggregateSigsSecure(
        std::vector<BLSSignature> const &sigs,
        std::vector<BLSPublicKey> const &pubKeys,
        std::vector<uint8_t*> const &messageHashes) {
    if (sigs.size() != pubKeys.size() || sigs.size() != messageHashes.size()
        || sigs.size() < 1) {
        throw std::string("Must have atleast one signature, key, and message");
    }

    // Sort the public keys and signature by message + public key
    std::vector<uint8_t*> serPubKeys(pubKeys.size());
    std::vector<uint8_t*> sortKeys(pubKeys.size());
    std::vector<size_t> keysSorted(pubKeys.size());
    for (size_t i = 0; i < pubKeys.size(); i++) {
        serPubKeys[i] = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
        pubKeys[i].Serialize(serPubKeys[i]);

        uint8_t *sortKey = new uint8_t[BLS::MESSAGE_HASH_LEN + BLSPublicKey::PUBLIC_KEY_SIZE];
        memcpy(sortKey, messageHashes[i], BLS::MESSAGE_HASH_LEN);
        memcpy(sortKey + BLS::MESSAGE_HASH_LEN, serPubKeys[i], BLSPublicKey::PUBLIC_KEY_SIZE);

        sortKeys[i] = sortKey;
        keysSorted[i] = i;
    }

    std::sort(keysSorted.begin(), keysSorted.end(), [&sortKeys](size_t a, size_t b) {
        return memcmp(sortKeys[a], sortKeys[b], BLS::MESSAGE_HASH_LEN + BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
    });

    relic::bn_t* computedTs = new relic::bn_t[keysSorted.size()];
    for (size_t i = 0; i < keysSorted.size(); i++) {
        relic::bn_new(computedTs[i]);
    }
    BLS::HashPubKeys(computedTs, keysSorted.size(), serPubKeys, keysSorted);

    // Copy each signature into sig, raise to power of each t for
    // sigComp, and multiply all together into aggSig
    BLSInsecureSignature sig, sigComp, aggSig;

    for (size_t i = 0; i < keysSorted.size(); i++) {
        aggSig = aggSig.Aggregate(sigs[keysSorted[i]].sig.Mul(computedTs[i]));
    }
    delete[] computedTs;

    for (auto p : serPubKeys) {
        delete[] p;
    }
    for (auto p : sortKeys) {
        delete[] p;
    }

    BLSSignature ret = BLSSignature::FromInsecureSig(aggSig);
    BLS::CheckRelicErrors();
    return ret;
}

BLSSignature BLSSignature::AggregateSigsInternal(
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
    std::vector<size_t> sigsSorted(collidingSigs.size());
    for (size_t i = 0; i < sigsSorted.size(); i++) {
        sigsSorted[i] = i;
    }
    std::sort(sigsSorted.begin(), sigsSorted.end(), [&collidingSigs](size_t a, size_t b) {
        return *collidingSigs[a].GetAggregationInfo() < *collidingSigs[b].GetAggregationInfo();
    });

    std::vector<uint8_t*> serPubKeys;
    std::vector<uint8_t*> sortKeys;
    std::vector<size_t> sortKeysSorted;
    size_t sortKeysCount = 0;
    for (size_t i = 0; i < collidingPks.size(); i++) {
        sortKeysCount += collidingPks[i].size();
    }
    sortKeys.reserve(sortKeysCount);
    sortKeysSorted.reserve(sortKeysCount);
    for (size_t i = 0; i < collidingPks.size(); i++) {
        for (size_t j = 0; j < collidingPks[i].size(); j++) {
            uint8_t *serPk = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
            uint8_t *sortKey = new uint8_t[BLS::MESSAGE_HASH_LEN + BLSPublicKey::PUBLIC_KEY_SIZE];
            collidingPks[i][j].Serialize(serPk);
            std::memcpy(sortKey, collidingMessageHashes[i][j], BLS::MESSAGE_HASH_LEN);
            std::memcpy(sortKey + BLS::MESSAGE_HASH_LEN, serPk, BLSPublicKey::PUBLIC_KEY_SIZE);
            serPubKeys.emplace_back(serPk);
            sortKeysSorted.emplace_back(sortKeys.size());
            sortKeys.emplace_back(sortKey);
        }
    }
    // Sort everything according to message || pubkey
    std::sort(sortKeysSorted.begin(), sortKeysSorted.end(), [&sortKeys](size_t a, size_t b) {
        return memcmp(sortKeys[a], sortKeys[b], BLS::MESSAGE_HASH_LEN + BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
    });

    std::vector<BLSPublicKey> pubKeysSorted;
    for (size_t i = 0; i < sortKeysSorted.size(); i++) {
        const uint8_t *sortKey = sortKeys[sortKeysSorted[i]];
        pubKeysSorted.push_back(BLSPublicKey::FromBytes(sortKey
                                                        + BLS::MESSAGE_HASH_LEN));
    }
    relic::bn_t* computedTs = new relic::bn_t[sigsSorted.size()];
    for (size_t i = 0; i < sigsSorted.size(); i++) {
        bn_new(computedTs[i]);
    }
    BLS::HashPubKeys(computedTs, sigsSorted.size(), serPubKeys, sortKeysSorted);

    // Copy each signature into sig, raise to power of each t for
    // sigComp, and multiply all together into aggSig
    BLSInsecureSignature sig, sigComp, aggSig;
    std::vector<AggregationInfo> infos;

    // Also accumulates aggregation info for each signature
    for (size_t i = 0; i < sigsSorted.size(); i++) {
        const BLSSignature& s = collidingSigs[sigsSorted[i]];
        aggSig = aggSig.Aggregate(s.sig.Mul(computedTs[i]));
        infos.push_back(*s.GetAggregationInfo());
    }

    for (const BLSSignature &nonColliding : nonCollidingSigs) {
        aggSig = aggSig.Aggregate(nonColliding.sig);
        infos.push_back(*nonColliding.GetAggregationInfo());
    }
    BLSSignature ret = BLSSignature::FromInsecureSig(aggSig);

    // Merge the aggregation infos, which will be combined in an
    // identical way as above.
    ret.SetAggregationInfo(AggregationInfo::MergeInfos(infos));

    delete[] computedTs;

    for (auto p : serPubKeys) {
        delete[] p;
    }
    for (auto p : sortKeys) {
        delete[] p;
    }

    return ret;
}

BLSSignature BLSSignature::AggregateSigsSimple(std::vector<BLSSignature> const &sigs) {
    if (sigs.size() < 1) {
        throw std::string("Must have atleast one signatures and key");
    }
    if (sigs.size() == 1) {
        return sigs[0];
    }

    BLSInsecureSignature aggSig;

    // Multiplies the signatures together (relic uses additive group operation)
    for (const BLSSignature &sig : sigs) {
        aggSig = aggSig.Aggregate(sig.sig);
    }
    BLSSignature ret = BLSSignature::FromInsecureSig(aggSig);
    BLS::CheckRelicErrors();
    return ret;
}

BLSSignature BLSSignature::DivideBy(std::vector<BLSSignature> const &divisorSigs) const {
    relic::bn_t ord;
    g2_get_ord(ord);

    std::vector<uint8_t*> messageHashesToRemove;
    std::vector<BLSPublicKey> pubKeysToRemove;

    BLSInsecureSignature prod;
    for (const BLSSignature &divisorSig : divisorSigs) {
        std::vector<BLSPublicKey> pks = divisorSig.GetAggregationInfo()
                ->GetPubKeys();
        std::vector<uint8_t*> messageHashes = divisorSig.GetAggregationInfo()
                ->GetMessageHashes();
        if (pks.size() != messageHashes.size()) {
            throw string("Invalid aggregation info.");
        }
        relic::bn_t quotient;
        for (size_t i = 0; i < pks.size(); i++) {
            relic::bn_t divisor;
            bn_new(divisor);
            divisorSig.GetAggregationInfo()->GetExponent(&divisor,
                    messageHashes[i],
                    pks[i]);
            relic::bn_t dividend;
            bn_new(dividend);
            try {
                aggregationInfo.GetExponent(&dividend, messageHashes[i],
                                            pks[i]);
            } catch (std::out_of_range e) {
                throw string("Signature is not a subset.");
            }

            relic::bn_t inverted;
            relic::fp_inv_exgcd_bn(inverted, divisor, ord);

            if (i == 0) {
                relic::bn_mul(quotient, dividend, inverted);
                relic::bn_mod(quotient, quotient, ord);
            } else {
                relic::bn_t newQuotient;
                relic::bn_mul(newQuotient, dividend, inverted);
                relic::bn_mod(newQuotient, newQuotient, ord);

                if (relic::bn_cmp(quotient, newQuotient) != CMP_EQ) {
                    throw string("Cannot divide by aggregate signature,"
                                 "msg/pk pairs are not unique");
                }
            }
            messageHashesToRemove.push_back(messageHashes[i]);
            pubKeysToRemove.push_back(pks[i]);
        }
        BLSInsecureSignature newSig = divisorSig.sig.Mul(quotient);
        prod = prod.DivideBy(newSig);
    }

    prod = sig.Aggregate(prod);

    BLSSignature result = BLSSignature::FromInsecureSig(prod, aggregationInfo);
    result.aggregationInfo.RemoveEntries(messageHashesToRemove, pubKeysToRemove);

    return result;
}

