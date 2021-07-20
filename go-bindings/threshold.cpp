// Copyright 2019 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "threshold.h"
#include <vector>
#include "bls.hpp"

CPrivateKey CThresholdCreate(
    void **commitments,
    void **secretFragments,
    size_t T,
    size_t N
) {
    std::vector<bls::PublicKey> vecCommitments = std::vector<bls::PublicKey>();
    std::vector<bls::PrivateKey> vecSecretFragments =
        std::vector<bls::PrivateKey>();

    for (size_t j = 0; j < N; ++j) {
        if (j < T) {
            g1_t g;
            vecCommitments.emplace_back(bls::PublicKey::FromG1(&g));
        }
        bn_t b;
        bn_new(b);
        vecSecretFragments.emplace_back(bls::PrivateKey::FromBN(b));
    }

    bls::PrivateKey* key = new bls::PrivateKey(
        bls::Threshold::Create(vecCommitments, vecSecretFragments, T, N)
    );

    // get pointers to commitments
    for (size_t i = 0; i < vecCommitments.size(); ++i) {
        commitments[i] = static_cast<void*>(
            new bls::PublicKey(vecCommitments[i]));
    }

    // get pointers to fragments
    for (size_t i = 0; i < vecSecretFragments.size(); ++i) {
        secretFragments[i] = static_cast<void*>(
            new bls::PrivateKey(vecSecretFragments[i]));
    }

    return key;
}

void** CThresholdLagrangeCoeffsAtZero(size_t *players, size_t T) {
    bn_t *coeffs = new bn_t[T];
    try {
        bls::Threshold::LagrangeCoeffsAtZero(coeffs, players, T);
    } catch (const std::exception& e) {
        delete[] coeffs;
        throw e;
    }

    // these use Fr (field element w/RFieldModulus, or `n`), which is used by
    // private key and occupy same size bytes
    uint8_t **buffer = static_cast<uint8_t**>(
        malloc(bls::PrivateKey::PRIVATE_KEY_SIZE * T));

    for (int i = 0; i < T; ++i) {
        bn_write_bin(buffer[i], bls::PrivateKey::PRIVATE_KEY_SIZE, coeffs[i]);
    }

    delete[] coeffs;
    return reinterpret_cast<void**>(buffer);
}

void* CThresholdInterpolateAtZero(size_t *X, CBigNum *Y, size_t T) {
    bn_t *res = new bn_t[1];
    bn_new(*res);

    bls::Threshold::InterpolateAtZero(res[0], X, reinterpret_cast<bn_t*>(Y), T);

    uint8_t* buffer = static_cast<uint8_t*>(
        malloc(bls::PrivateKey::PRIVATE_KEY_SIZE));

    bn_write_bin(buffer, bls::PrivateKey::PRIVATE_KEY_SIZE, res[0]);

    delete[] res;

    return static_cast<void*>(buffer);
}

bool CThresholdVerifySecretFragment(size_t player, CPrivateKey secretFragment,
    void ** commitments, size_t numCommitments, size_t T) {

    // build commitments vector
    std::vector<bls::PublicKey> vecCommitments;
    for (int i = 0 ; i < numCommitments; i++) {
        bls::PublicKey* key = (bls::PublicKey*)commitments[i];
        vecCommitments.push_back(*key);
    }

    bls::PrivateKey* key = (bls::PrivateKey*)secretFragment;

    return bls::Threshold::VerifySecretFragment(player, *key, vecCommitments,
        T);
}

CInsecureSignature CThresholdSignWithCoefficient(CPrivateKey skPtr, void *msg,
    size_t len, size_t player, size_t *players, size_t T) {
    bls::PrivateKey *key = (bls::PrivateKey *)skPtr;

    bls::InsecureSignature *sig = new bls::InsecureSignature(
        bls::Threshold::SignWithCoefficient(*key, static_cast<uint8_t*>(msg),
            len, player, players, T)
    );

    return sig;
}

CInsecureSignature CThresholdAggregateUnitSigs(void **sigs, size_t numSigs,
    void *msg, size_t len, size_t *players, size_t T) {
    // build signatures vector
    std::vector<bls::InsecureSignature> vecSignatures;
    for (int i = 0 ; i < numSigs; i++) {
        bls::InsecureSignature* sig = (bls::InsecureSignature*)sigs[i];
        vecSignatures.push_back(*sig);
    }

    bls::InsecureSignature *sig = new bls::InsecureSignature(
        bls::Threshold::AggregateUnitSigs(vecSignatures,
            static_cast<uint8_t*>(msg), len, players, T)
    );

    return sig;
}


size_t* AllocIntPtr(size_t size) {
    return static_cast<size_t*>(malloc(sizeof(size_t) * size));
}

void SetIntPtrVal(size_t *ptr, size_t value, int index) {
    ptr[index] = value;
}

size_t GetIntPtrVal(size_t *ptr, int index) {
    return ptr[index];
}

void FreeIntPtr(size_t *ptr) {
    free(static_cast<void*>(ptr));
}
