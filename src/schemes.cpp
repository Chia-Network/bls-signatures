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

#include <algorithm>
#include <cstring>
#include <set>
#include <string>

#include "bls.hpp"
#include "elements.hpp"
#include "schemes.hpp"
#include "hdkeys.hpp"

using std::string;
using std::vector;

namespace bls {

enum InvariantResult { BAD=false, GOOD=true, CONTINUE };

// Enforce argument invariants for Agg Sig Verification
InvariantResult VerifyAggregateSignatureArguments(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,  // unhashed
    const G2Element &signature)
{
    int n = pubkeys.size();

    if (n == 0) {
      return (messages.empty() && signature == G2Element::Infinity() ? GOOD : BAD);
    }
    if (n != messages.size() || n <= 0) {
        return BAD;
    }
    return CONTINUE;
}

InvariantResult VerifyAggregateSignatureArguments(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,  // unhashed
    const vector<uint8_t> &signature)
{
    vector<G1Element> pubkeyElements;
    int n = pubkeys.size();
    for (int i = 0; i < n; ++i) {
        pubkeyElements.push_back(G1Element::FromBytes(pubkeys[i].data()));
    }
    G2Element signatureElement = G2Element::FromBytes(signature.data());
    return VerifyAggregateSignatureArguments(pubkeyElements, messages, signatureElement);
}

/* These are all for the min-pubkey-size variant.
   TODO : analogs for min-signature-size
*/
const uint8_t *BasicSchemeMPL::CIPHERSUITE_ID =
    (const uint8_t *)"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const int BasicSchemeMPL::CIPHERSUITE_ID_LEN = 43;
const uint8_t *AugSchemeMPL::CIPHERSUITE_ID =
    (const uint8_t *)"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
const int AugSchemeMPL::CIPHERSUITE_ID_LEN = 43;
const uint8_t *PopSchemeMPL::CIPHERSUITE_ID =
    (const uint8_t *)"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const int PopSchemeMPL::CIPHERSUITE_ID_LEN = 43;
const uint8_t *PopSchemeMPL::POP_CIPHERSUITE_ID =
    (const uint8_t *)"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const int PopSchemeMPL::POP_CIPHERSUITE_ID_LEN = 43;

PrivateKey CoreMPL::KeyGen(const vector<uint8_t> seed) {
    return HDKeys::KeyGen(seed);
}

vector<uint8_t> CoreMPL::SkToPk(const PrivateKey &seckey)
{
    return seckey.GetG1Element().Serialize();
}

G1Element CoreMPL::SkToG1(const PrivateKey &seckey)
{
    return seckey.GetG1Element();
}

G2Element CoreMPL::Sign(
    const PrivateKey &seckey,
    const vector<uint8_t> &message,
    const uint8_t *dst,
    int dst_len)
{
    return seckey.SignG2(message.data(), message.size(), dst, dst_len);
}

bool CoreMPL::Verify(
    const vector<uint8_t> &pubkey,
    const vector<uint8_t> &message,  // unhashed
    const vector<uint8_t> &signature,
    const uint8_t *dst,
    int dst_len)
{
    return CoreMPL::Verify(
        G1Element::FromBytes(pubkey.data()),
        message,
        G2Element::FromBytes(signature.data()),
        dst,
        dst_len);
}

bool CoreMPL::Verify(
    const G1Element &pubkey,
    const vector<uint8_t> &message,  // unhashed
    const G2Element &signature,
    const uint8_t *dst,
    int dst_len)
{
    G1Element genneg = G1Element::Generator().Negate();
    G2Element hashedPoint = G2Element::FromMessage(message, dst, dst_len);

    g1_t *g1s = new g1_t[2];
    g2_t *g2s = new g2_t[2];

    genneg.ToNative(g1s);
    pubkey.ToNative(g1s + 1);
    signature.ToNative(g2s);
    hashedPoint.ToNative(g2s + 1);

    bool ans = CoreMPL::NativeVerify(g1s, g2s, 2);

    delete[] g1s;
    delete[] g2s;
    return ans;
}

vector<uint8_t> CoreMPL::Aggregate(const vector<vector<uint8_t>> &signatures)
{
    vector<G2Element> elements = vector<G2Element>();
    for (vector<uint8_t> signature : signatures) {
        elements.push_back(G2Element::FromByteVector(signature));
    }
    return CoreMPL::Aggregate(elements).Serialize();
}

G2Element CoreMPL::Aggregate(const vector<G2Element> &signatures)
{
    g2_t ans, tmp;
    int n = (int)signatures.size();
    if (n <= 0) {
        g2_set_infty(ans);
        return G2Element::FromNative(&ans);
    }

    signatures[0].ToNative(&ans);

    for (int i = 1; i < n; ++i) {
        signatures[i].ToNative(&tmp);
        g2_add(ans, ans, tmp);
    }
    return G2Element::FromNative(&ans);
}

G1Element CoreMPL::Aggregate(const vector<G1Element> &publicKeys)
{
    g1_t ans, tmp;
    int n = (int)publicKeys.size();
    if (n <= 0) {
        g1_set_infty(ans);
        return G1Element::FromNative(&ans);
    }

    publicKeys[0].ToNative(&ans);

    for (int i = 1; i < n; ++i) {
        publicKeys[i].ToNative(&tmp);
        g1_add(ans, ans, tmp);
    }
    return G1Element::FromNative(&ans);
}

bool CoreMPL::AggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,  // unhashed
    const vector<uint8_t> &signature,
    const uint8_t *dst,
    int dst_len)
{
    int n = pubkeys.size();
    if (n <= 0 || n != messages.size()) {
        return VerifyAggregateSignatureArguments(pubkeys, messages, signature);
    }

    vector<G1Element> pubkeyElements;
    for (int i = 0; i < n; ++i) {
        pubkeyElements.push_back(G1Element::FromBytes(pubkeys[i].data()));
    }
    G2Element signatureElement = G2Element::FromBytes(signature.data());
    return CoreMPL::AggregateVerify(
        pubkeyElements, messages, signatureElement, dst, dst_len);
}

bool CoreMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,  // unhashed
    const G2Element &signature,
    const uint8_t *dst,
    int dst_len)
{
    int n = pubkeys.size();
    if (n <= 0 || n != messages.size()) {
        return VerifyAggregateSignatureArguments(pubkeys, messages, signature);
    }

    g1_t *g1s = new g1_t[n + 1];
    g2_t *g2s = new g2_t[n + 1];

    G1Element genneg = G1Element::Generator().Negate();

    genneg.ToNative(g1s);
    signature.ToNative(g2s);

    for (int i = 0; i < n; ++i) {
        pubkeys[i].ToNative(g1s + i + 1);
        G2Element::FromMessage(messages[i], dst, dst_len).ToNative(g2s + i + 1);
    }

    bool ans = CoreMPL::NativeVerify(g1s, g2s, n + 1);
    delete[] g1s;
    delete[] g2s;
    return ans;
}

bool CoreMPL::NativeVerify(g1_t *pubkeys, g2_t *mappedHashes, size_t length)
{
    gt_t target, candidate, tmpPairing;
    fp12_zero(target);
    fp_set_dig(target[0][0][0], 1);
    fp12_zero(candidate);
    fp_set_dig(candidate[0][0][0], 1);

    // prod e(pubkey[i], hash[i]) * e(-g1, aggSig)
    // Performs pubKeys.size() pairings, 250 at a time

    for (size_t i = 0; i < length; i += 250) {
        size_t numPairings = std::min((length - i), (size_t)250);
        pc_map_sim(tmpPairing, pubkeys + i, mappedHashes + i, numPairings);
        fp12_mul(candidate, candidate, tmpPairing);
    }

    // 1 =? prod e(pubkey[i], hash[i]) * e(-g1, aggSig)
    if (gt_cmp(target, candidate) != RLC_EQ || core_get()->code != RLC_OK) {
        core_get()->code = RLC_OK;
        return false;
    }
    BLS::CheckRelicErrors();
    return true;
}

PrivateKey CoreMPL::DeriveChildSk(const PrivateKey& sk, uint32_t index) {
    return HDKeys::DeriveChildSk(sk, index);
}

PrivateKey CoreMPL::DeriveChildSkUnhardened(const PrivateKey& sk, uint32_t index) {
    return HDKeys::DeriveChildSkUnhardened(sk, index);
}

G1Element CoreMPL::DeriveChildPkUnhardened(const G1Element& pk, uint32_t index) {
    return HDKeys::DeriveChildG1Unhardened(pk, index);
}

G2Element BasicSchemeMPL::Sign(
    const PrivateKey &seckey,
    const vector<uint8_t> &message)
{
    return CoreMPL::Sign(
        seckey,
        message,
        BasicSchemeMPL::CIPHERSUITE_ID,
        BasicSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool BasicSchemeMPL::Verify(
    const vector<uint8_t> &pubkey,
    const vector<uint8_t> &message,
    const vector<uint8_t> &signature)
{
    return CoreMPL::Verify(
        pubkey,
        message,
        signature,
        BasicSchemeMPL::CIPHERSUITE_ID,
        BasicSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool BasicSchemeMPL::Verify(
    const G1Element &pubkey,
    const vector<uint8_t> &message,
    const G2Element &signature)
{
    return CoreMPL::Verify(
        pubkey,
        message,
        signature,
        BasicSchemeMPL::CIPHERSUITE_ID,
        BasicSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool BasicSchemeMPL::AggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const vector<uint8_t> &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(pubkeys, messages, signature);
    if (arg_check != CONTINUE) return arg_check;

    std::set<vector<uint8_t>> s(messages.begin(), messages.end());
    if (s.size() != n)
        return false;
    return CoreMPL::AggregateVerify(
        pubkeys,
        messages,
        signature,
        BasicSchemeMPL::CIPHERSUITE_ID,
        BasicSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool BasicSchemeMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const G2Element &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(pubkeys, messages, signature);
    if (arg_check != CONTINUE) return arg_check;

    std::set<vector<uint8_t>> s(messages.begin(), messages.end());
    if (s.size() != n) {
        return false;
    }
    return CoreMPL::AggregateVerify(
        pubkeys,
        messages,
        signature,
        BasicSchemeMPL::CIPHERSUITE_ID,
        BasicSchemeMPL::CIPHERSUITE_ID_LEN);
}

G2Element AugSchemeMPL::Sign(
    const PrivateKey &seckey,
    const vector<uint8_t> &message)
{
    vector<uint8_t> augMessage = seckey.GetG1Element().Serialize();
    augMessage.reserve(
        augMessage.size() + std::distance(message.begin(), message.end()));
    augMessage.insert(augMessage.end(), message.begin(), message.end());
    return seckey.SignG2(
        augMessage.data(),
        augMessage.size(),
        AugSchemeMPL::CIPHERSUITE_ID,
        AugSchemeMPL::CIPHERSUITE_ID_LEN);
}

// Used for prepending different augMessage
G2Element AugSchemeMPL::Sign(
    const PrivateKey &seckey,
    const vector<uint8_t> &message,
    const G1Element &prepend_pk)
{
    vector<uint8_t> augMessage = prepend_pk.Serialize();
    augMessage.reserve(
        augMessage.size() + std::distance(message.begin(), message.end()));
    augMessage.insert(augMessage.end(), message.begin(), message.end());
    return seckey.SignG2(
        augMessage.data(),
        augMessage.size(),
        AugSchemeMPL::CIPHERSUITE_ID,
        AugSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool AugSchemeMPL::Verify(
    const vector<uint8_t> &pubkey,
    const vector<uint8_t> &message,
    const vector<uint8_t> &signature)
{
    vector<uint8_t> augMessage(pubkey);
    augMessage.reserve(
        augMessage.size() + std::distance(message.begin(), message.end()));
    augMessage.insert(augMessage.end(), message.begin(), message.end());
    return CoreMPL::Verify(
        pubkey,
        augMessage,
        signature,
        AugSchemeMPL::CIPHERSUITE_ID,
        AugSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool AugSchemeMPL::Verify(
    const G1Element &pubkey,
    const vector<uint8_t> &message,
    const G2Element &signature)
{
    vector<uint8_t> augMessage(pubkey.Serialize());
    augMessage.reserve(
        augMessage.size() + std::distance(message.begin(), message.end()));
    augMessage.insert(augMessage.end(), message.begin(), message.end());
    return CoreMPL::Verify(
        pubkey,
        augMessage,
        signature,
        AugSchemeMPL::CIPHERSUITE_ID,
        AugSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool AugSchemeMPL::AggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const vector<uint8_t> &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(pubkeys, messages, signature);
    if (arg_check != CONTINUE) return arg_check;

    vector<vector<uint8_t>> augMessages(n);
    for (int i = 0; i < n; ++i) {
        vector<uint8_t> aug(pubkeys[i]);
        aug.reserve(
            aug.size() + std::distance(messages[i].begin(), messages[i].end()));
        aug.insert(aug.end(), messages[i].begin(), messages[i].end());
        augMessages[i] = aug;
    }

    return CoreMPL::AggregateVerify(
        pubkeys,
        const_cast<const vector<vector<uint8_t>> &>(augMessages),
        signature,
        AugSchemeMPL::CIPHERSUITE_ID,
        AugSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool AugSchemeMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const G2Element &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(pubkeys, messages, signature);
    if (arg_check != CONTINUE) return arg_check;

    vector<vector<uint8_t>> augMessages(n);
    for (int i = 0; i < n; ++i) {
        vector<uint8_t> aug(pubkeys[i].Serialize());
        aug.reserve(
            aug.size() + std::distance(messages[i].begin(), messages[i].end()));
        aug.insert(aug.end(), messages[i].begin(), messages[i].end());
        augMessages[i] = aug;
    }

    return CoreMPL::AggregateVerify(
        pubkeys,
        const_cast<const vector<vector<uint8_t>> &>(augMessages),
        signature,
        AugSchemeMPL::CIPHERSUITE_ID,
        AugSchemeMPL::CIPHERSUITE_ID_LEN);
}

G2Element PopSchemeMPL::Sign(
    const PrivateKey &seckey,
    const vector<uint8_t> &message)
{
    return CoreMPL::Sign(
        seckey,
        message,
        PopSchemeMPL::CIPHERSUITE_ID,
        PopSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool PopSchemeMPL::Verify(
    const vector<uint8_t> &pubkey,
    const vector<uint8_t> &message,
    const vector<uint8_t> &signature)
{
    return CoreMPL::Verify(
        pubkey,
        message,
        signature,
        PopSchemeMPL::CIPHERSUITE_ID,
        PopSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool PopSchemeMPL::Verify(
    const G1Element &pubkey,
    const vector<uint8_t> &message,
    const G2Element &signature)
{
    return CoreMPL::Verify(
        pubkey,
        message,
        signature,
        PopSchemeMPL::CIPHERSUITE_ID,
        PopSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool PopSchemeMPL::AggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const vector<uint8_t> &signature)
{
    return CoreMPL::AggregateVerify(
        pubkeys,
        messages,
        signature,
        PopSchemeMPL::CIPHERSUITE_ID,
        PopSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool PopSchemeMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const G2Element &signature)
{
    return CoreMPL::AggregateVerify(
        pubkeys,
        messages,
        signature,
        PopSchemeMPL::CIPHERSUITE_ID,
        PopSchemeMPL::CIPHERSUITE_ID_LEN);
}

G2Element PopSchemeMPL::PopProve(const PrivateKey &seckey)
{
    G1Element pk = seckey.GetG1Element();
    G2Element hashedKey = G2Element::FromMessage(
        pk.Serialize(),
        PopSchemeMPL::POP_CIPHERSUITE_ID,
        PopSchemeMPL::POP_CIPHERSUITE_ID_LEN);

    return seckey.GetG2Power(hashedKey);
}


bool PopSchemeMPL::PopVerify(
    const G1Element &pubkey,
    const G2Element &signature_proof)
{
    G1Element genneg = G1Element::Generator().Negate();
    G2Element hashedPoint = G2Element::FromMessage(
        pubkey.Serialize(),
        PopSchemeMPL::POP_CIPHERSUITE_ID,
        PopSchemeMPL::POP_CIPHERSUITE_ID_LEN);

    g1_t *g1s = new g1_t[2];
    g2_t *g2s = new g2_t[2];
    genneg.ToNative(g1s);
    pubkey.ToNative(g1s + 1);
    signature_proof.ToNative(g2s);
    hashedPoint.ToNative(g2s + 1);

    bool ans = CoreMPL::NativeVerify(g1s, g2s, 2);
    delete[] g1s;
    delete[] g2s;
    return ans;
}

bool PopSchemeMPL::PopVerify(
    const vector<uint8_t> &pubkey,
    const vector<uint8_t> &proof)
{
    G1Element p = G1Element::FromBytes(pubkey.data());
    G2Element q = G2Element::FromBytes(proof.data());
    return PopSchemeMPL::PopVerify(p, q);
}

bool PopSchemeMPL::FastAggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<uint8_t> &message,
    const G2Element &signature)
{
    G1Element pkagg = CoreMPL::Aggregate(pubkeys);

    int n = pubkeys.size();

    const vector<vector<uint8_t>> messages = { message };
    const vector<G1Element> pkelements = { pkagg };

    if (pubkeys.size() <= 0) return false;
    auto arg_check = VerifyAggregateSignatureArguments(pkelements, messages, signature);
    if (arg_check != CONTINUE) return arg_check;

    return CoreMPL::Verify(
        pkagg,
        message,
        signature,
        PopSchemeMPL::CIPHERSUITE_ID,
        PopSchemeMPL::CIPHERSUITE_ID_LEN);
}

bool PopSchemeMPL::FastAggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<uint8_t> &message,
    const vector<uint8_t> &signature)
{
    int n = pubkeys.size();
    const vector<vector<uint8_t>> messages = { message };

    if (pubkeys.size() <= 0) return false;

    vector<G1Element> pkelements;
    for (int i = 0; i < n; ++i) {
        pkelements.push_back(G1Element::FromBytes(pubkeys[i].data()));
    }

    return PopSchemeMPL::FastAggregateVerify(
        pkelements, message, G2Element::FromBytes(signature.data()));
}
}  // end namespace bls
