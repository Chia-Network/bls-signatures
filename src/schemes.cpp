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
    const size_t nPubKeys,
    const size_t nMessages,
    const G2Element &signature)
{
    if (nPubKeys == 0) {
        return (nMessages == 0 && signature == G2Element::Infinity() ? GOOD : BAD);
    }
    if (nPubKeys != nMessages || nPubKeys <= 0) {
        return BAD;
    }
    return CONTINUE;
}

/* These are all for the min-pubkey-size variant.
   TODO : analogs for min-signature-size
*/
const std::string BasicSchemeMPL::CIPHERSUITE_ID = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const std::string AugSchemeMPL::CIPHERSUITE_ID = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
const std::string PopSchemeMPL::CIPHERSUITE_ID = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const std::string PopSchemeMPL::POP_CIPHERSUITE_ID = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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

G2Element CoreMPL::Sign(const PrivateKey &seckey, const vector<uint8_t> &message)
{
    return seckey.SignG2(message.data(), message.size(), (const uint8_t*)strCiphersuiteId.c_str(), strCiphersuiteId.length());
}

bool CoreMPL::Verify(
    const vector<uint8_t> &pubkey,
    const vector<uint8_t> &message,  // unhashed
    const vector<uint8_t> &signature)
{
    return CoreMPL::Verify(G1Element::FromBytes(pubkey.data()),
                           message,
                           G2Element::FromBytes(signature.data()));
}

bool CoreMPL::Verify(
    const G1Element &pubkey,
    const vector<uint8_t> &message,  // unhashed
    const G2Element &signature)
{
    G1Element genneg = G1Element::Generator().Negate();
    G2Element hashedPoint = G2Element::FromMessage(message, (const uint8_t*)strCiphersuiteId.c_str(), strCiphersuiteId.length());

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
    const vector<uint8_t> &signature)
{
    int n = pubkeys.size();
    G2Element signatureElement = G2Element::FromByteVector(signature);
    if (n <= 0 || n != messages.size()) {
        return VerifyAggregateSignatureArguments(n, messages.size(), signatureElement);
    }

    vector<G1Element> pubkeyElements;
    for (int i = 0; i < n; ++i) {
        pubkeyElements.push_back(G1Element::FromBytes(pubkeys[i].data()));
    }
    return CoreMPL::AggregateVerify(pubkeyElements, messages, signatureElement);
}

bool CoreMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,  // unhashed
    const G2Element &signature)
{
    int n = pubkeys.size();
    if (n <= 0 || n != messages.size()) {
        return VerifyAggregateSignatureArguments(pubkeys.size(), messages.size(), signature);
    }

    g1_t *g1s = new g1_t[n + 1];
    g2_t *g2s = new g2_t[n + 1];

    G1Element genneg = G1Element::Generator().Negate();

    genneg.ToNative(g1s);
    signature.ToNative(g2s);

    for (int i = 0; i < n; ++i) {
        pubkeys[i].ToNative(g1s + i + 1);
        G2Element::FromMessage(messages[i], (const uint8_t*)strCiphersuiteId.c_str(), strCiphersuiteId.length()).ToNative(g2s + i + 1);
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

bool BasicSchemeMPL::AggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const vector<uint8_t> &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(n, messages.size(), G2Element::FromByteVector(signature));
    if (arg_check != CONTINUE) return arg_check;

    std::set<vector<uint8_t>> s(messages.begin(), messages.end());
    if (s.size() != n)
        return false;
    return CoreMPL::AggregateVerify(pubkeys, messages, signature);
}

bool BasicSchemeMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const G2Element &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(n, messages.size(), signature);
    if (arg_check != CONTINUE) return arg_check;

    std::set<vector<uint8_t>> s(messages.begin(), messages.end());
    if (s.size() != n) {
        return false;
    }
    return CoreMPL::AggregateVerify(pubkeys, messages, signature);
}

G2Element AugSchemeMPL::Sign(
    const PrivateKey &seckey,
    const vector<uint8_t> &message)
{
    vector<uint8_t> augMessage = seckey.GetG1Element().Serialize();
    augMessage.reserve(
        augMessage.size() + std::distance(message.begin(), message.end()));
    augMessage.insert(augMessage.end(), message.begin(), message.end());
    return CoreMPL::Sign(seckey, augMessage);
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
    return CoreMPL::Sign(seckey, augMessage);
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
    return CoreMPL::Verify(pubkey, augMessage, signature);
}

bool AugSchemeMPL::Verify(
    const G1Element &pubkey,
    const vector<uint8_t> &message,
    const G2Element &signature)
{
    return Verify(pubkey.Serialize(), message, signature.Serialize());
}

bool AugSchemeMPL::AggregateVerify(
    const vector<vector<uint8_t>> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const vector<uint8_t> &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(n, messages.size(), G2Element::FromByteVector(signature));
    if (arg_check != CONTINUE) return arg_check;

    vector<vector<uint8_t>> augMessages(n);
    for (int i = 0; i < n; ++i) {
        vector<uint8_t> aug(pubkeys[i]);
        aug.reserve(
            aug.size() + std::distance(messages[i].begin(), messages[i].end()));
        aug.insert(aug.end(), messages[i].begin(), messages[i].end());
        augMessages[i] = aug;
    }

    return CoreMPL::AggregateVerify(pubkeys, augMessages, signature);
}

bool AugSchemeMPL::AggregateVerify(
    const vector<G1Element> &pubkeys,
    const vector<vector<uint8_t>> &messages,
    const G2Element &signature)
{
    int n = pubkeys.size();
    auto arg_check = VerifyAggregateSignatureArguments(n, messages.size(), signature);
    if (arg_check != CONTINUE) return arg_check;

    vector<vector<uint8_t>> augMessages(n);
    for (int i = 0; i < n; ++i) {
        vector<uint8_t> aug(pubkeys[i].Serialize());
        aug.reserve(
            aug.size() + std::distance(messages[i].begin(), messages[i].end()));
        aug.insert(aug.end(), messages[i].begin(), messages[i].end());
        augMessages[i] = aug;
    }

    return CoreMPL::AggregateVerify(pubkeys, augMessages, signature);
}

G2Element PopSchemeMPL::PopProve(const PrivateKey &seckey)
{
    G1Element pk = seckey.GetG1Element();
    G2Element hashedKey = G2Element::FromMessage(pk.Serialize(), (const uint8_t *)POP_CIPHERSUITE_ID.c_str(), POP_CIPHERSUITE_ID.length());
    return seckey.GetG2Power(hashedKey);
}


bool PopSchemeMPL::PopVerify(
    const G1Element &pubkey,
    const G2Element &signature_proof)
{
    G1Element genneg = G1Element::Generator().Negate();
    G2Element hashedPoint = G2Element::FromMessage(pubkey.Serialize(), (const uint8_t*)POP_CIPHERSUITE_ID.c_str(), POP_CIPHERSUITE_ID.length());

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
    auto arg_check = VerifyAggregateSignatureArguments(pkelements.size(), messages.size(), signature);
    if (arg_check != CONTINUE) return arg_check;

    return CoreMPL::Verify(
        pkagg,
        message,
        signature);
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
