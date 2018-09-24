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
#include "blssignature.hpp"
#include "bls.hpp"

using std::string;
using relic::bn_t;
using relic::fp_t;

BLSSignature BLSSignature::FromBytes(const uint8_t *data) {
    BLS::AssertInitialized();
    BLSSignature sigObj = BLSSignature();
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

BLSSignature BLSSignature::FromBytes(const uint8_t *data,
                                     const AggregationInfo &info) {
    BLSSignature ret = FromBytes(data);
    ret.SetAggregationInfo(info);
    return ret;
}

BLSSignature BLSSignature::FromG2(relic::g2_t* element) {
    BLS::AssertInitialized();
    BLSSignature sigObj = BLSSignature();
    relic::g2_copy(sigObj.sig, *element);
    return sigObj;
}

BLSSignature BLSSignature::FromG2(relic::g2_t* element, const AggregationInfo& info) {
    BLSSignature ret = FromG2(element);
    ret.SetAggregationInfo(info);
    return ret;
}

BLSSignature::BLSSignature(const BLSSignature &signature) {
    BLS::AssertInitialized();
    g2_copy(sig, *(relic::g2_t*)&signature.sig);
    aggregationInfo = signature.aggregationInfo;
}

void BLSSignature::GetPoint(relic::g2_t output) const {
    BLS::AssertInitialized();
    *output = *sig;
}

const AggregationInfo* BLSSignature::GetAggregationInfo() const {
    return &aggregationInfo;
}

void BLSSignature::SetAggregationInfo(
        const AggregationInfo &newAggregationInfo) {
    aggregationInfo = newAggregationInfo;
}

BLSSignature BLSSignature::DivideBy(std::vector<BLSSignature> const &divisorSigs) const {
    relic::bn_t ord;
    g2_get_ord(ord);

    std::vector<uint8_t*> messageHashesToRemove;
    std::vector<BLSPublicKey> pubKeysToRemove;

    relic::g2_t prod;
    relic::g2_set_infty(prod);
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
        bn_neg(quotient, quotient);
        relic::g2_t newSig;
        divisorSig.GetPoint(newSig);
        g2_mul(newSig, newSig, quotient);
        g2_add(prod, prod, newSig);
    }

    g2_add(prod, *(relic::g2_t*)&sig, prod);

    BLSSignature result = BLSSignature::FromG2(&prod, aggregationInfo);
    result.aggregationInfo.RemoveEntries(messageHashesToRemove, pubKeysToRemove);

    return result;
}

void BLSSignature::Serialize(uint8_t* buffer) const {
    BLS::AssertInitialized();
    CompressPoint(buffer, &sig);
}

std::vector<uint8_t> BLSSignature::Serialize() const {
    std::vector<uint8_t> data(SIGNATURE_SIZE);
    Serialize(data.data());
    return data;
}

bool operator==(BLSSignature const &a, BLSSignature const &b) {
    BLS::AssertInitialized();
    return g2_cmp(*(relic::g2_t*)&a.sig, *(relic::g2_t*)b.sig) == CMP_EQ;
}

bool operator!=(BLSSignature const &a, BLSSignature const &b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, BLSSignature const &s) {
    BLS::AssertInitialized();
    uint8_t data[BLSSignature::SIGNATURE_SIZE];
    s.Serialize(data);
    return os << BLSUtil::HexStr(data, BLSSignature::SIGNATURE_SIZE);
}

BLSSignature& BLSSignature::operator=(const BLSSignature &rhs) {
    BLS::AssertInitialized();
    relic::g2_copy(sig, *(relic::g2_t*)&rhs.sig);
    aggregationInfo = rhs.aggregationInfo;
    return *this;
}

void BLSSignature::CompressPoint(uint8_t* result, const relic::g2_t* point) {
    uint8_t buffer[BLSSignature::SIGNATURE_SIZE + 1];
    g2_write_bin(buffer, BLSSignature::SIGNATURE_SIZE + 1, *(relic::g2_t*)point, 1);

    if (buffer[0] == 0x03) {
        buffer[1] |= 0x80;
    }
    std::memcpy(result, buffer + 1, SIGNATURE_SIZE);
}
