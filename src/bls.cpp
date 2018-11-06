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
namespace bls {

const char BLS::GROUP_ORDER[] =
        "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";

bool BLSInitResult = BLS::Init();

Util::SecureAllocCallback Util::secureAllocCallback;
Util::SecureFreeCallback Util::secureFreeCallback;

static void relic_core_initializer(void* ptr) {
    core_init();
    if (err_get_code() != STS_OK) {
        std::cout << "core_init() failed";
        // this will most likely crash the application...but there isn't much we can do
        throw std::string("core_init() failed");
    }

    const int r = ep_param_set_any_pairf();
    if (r != STS_OK) {
        std::cout << "ep_param_set_any_pairf() failed";
        // this will most likely crash the application...but there isn't much we can do
        throw std::string("ep_param_set_any_pairf() failed");
    }
}

bool BLS::Init() {
    if (ALLOC != AUTO) {
        std::cout << "Must have ALLOC == AUTO";
        throw std::string("Must have ALLOC == AUTO");
    }
#if BLSALLOC_SODIUM
    if (sodium_init() < 0) {
        std::cout << "libsodium init failed";
        throw std::string("libsodium init failed");
    }
    SetSecureAllocator(libsodium::sodium_malloc, libsodium::sodium_free);
#else
    SetSecureAllocator(malloc, free);
#endif

    core_set_thread_initializer(relic_core_initializer, nullptr);

    return true;
}

void BLS::SetSecureAllocator(Util::SecureAllocCallback allocCb, Util::SecureFreeCallback freeCb) {
    Util::secureAllocCallback = allocCb;
    Util::secureFreeCallback = freeCb;
}

void BLS::HashPubKeys(bn_t* output, size_t numOutputs,
                      std::vector<uint8_t*> const &serPubKeys,
                      std::vector<size_t> const& sortedIndices) {
    bn_t order;

    bn_new(order);
    g2_get_ord(order);

    uint8_t *pkBuffer = new uint8_t[serPubKeys.size() * PublicKey::PUBLIC_KEY_SIZE];

    for (size_t i = 0; i < serPubKeys.size(); i++) {
        memcpy(pkBuffer + i * PublicKey::PUBLIC_KEY_SIZE, serPubKeys[sortedIndices[i]], PublicKey::PUBLIC_KEY_SIZE);
    }

    uint8_t pkHash[32];
    Util::Hash256(pkHash, pkBuffer, serPubKeys.size() * PublicKey::PUBLIC_KEY_SIZE);
    for (size_t i = 0; i < numOutputs; i++) {
        uint8_t hash[32];
        uint8_t buffer[4 + 32];
        memset(buffer, 0, 4);
        // Set first 4 bytes to index, to generate different ts
        Util::IntToFourBytes(buffer, i);
        // Set next 32 bytes as the hash of all the public keys
        std::memcpy(buffer + 4, pkHash, 32);
        Util::Hash256(hash, buffer, 4 + 32);

        bn_read_bin(output[i], hash, 32);
        bn_mod_basic(output[i], output[i], order);
    }

    delete[] pkBuffer;

    CheckRelicErrors();
}

PublicKey BLS::DHKeyExchange(const PrivateKey& privKey, const PublicKey& pubKey) {
    if (!privKey.keydata) {
        throw std::string("keydata not initialized");
    }
    PublicKey ret = pubKey.Exp(*privKey.keydata);
    CheckRelicErrors();
    return ret;
}

void BLS::CheckRelicErrors() {
    if (!core_get()) {
        throw std::string("Library not initialized properly. Call BLS::Init()");
    }
    if (core_get()->code != STS_OK) {
        core_get()->code = STS_OK;
        throw std::string("Relic library error");
    }
}
} // end namespace bls
