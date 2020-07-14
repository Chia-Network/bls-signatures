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

#ifndef SRC_BLSHDKEYS_HPP_
#define SRC_BLSHDKEYS_HPP_

#include "relic_conf.h"
#include <math.h>

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "util.hpp"
#include "privatekey.hpp"
#include "hkdf.hpp"

namespace bls {

class HDKeys {
    /**
     * Implements HD keys as specified in EIP2333.
     **/
 public:
    static const uint8_t HASH_LEN = 32;

    static void IKMToLamportSk(uint8_t* outputLamportSk, const uint8_t* ikm, size_t ikmLen, const uint8_t* salt, size_t saltLen)  {
        // Expands the ikm to 255*32 bytes for the lamport sk
        const uint8_t info[1] = {0};
        HKDF256::ExtractExpand(outputLamportSk, 32 * 255, ikm, ikmLen, salt, saltLen, info, 0);
    }

    static void ParentSkToLamportPK(uint8_t* outputLamportPk, PrivateKey& parentSk, uint32_t index) {
        uint8_t* salt = Util::SecAlloc<uint8_t>(4);
        uint8_t* ikm = Util::SecAlloc<uint8_t>(32);
        uint8_t* notIkm = Util::SecAlloc<uint8_t>(32);
        uint8_t* lamport0 = Util::SecAlloc<uint8_t>(32 * 255);
        uint8_t* lamport1 = Util::SecAlloc<uint8_t>(32 * 255);

        Util::IntToFourBytes(salt, index);
        parentSk.Serialize(ikm);

        for (size_t i = 0; i < 32; i++) {  // Flips the bits
            notIkm[i] = ikm[i] ^ 0xff;
        }

        HDKeys::IKMToLamportSk(lamport0, ikm, 32, salt, 4);
        HDKeys::IKMToLamportSk(lamport1, notIkm, 32, salt, 4);

        uint8_t* lamportPk = Util::SecAlloc<uint8_t>(32 * 255 * 2);

        for (size_t i = 0; i < 255; i++) {
            Util::Hash256(lamportPk + i * 32, lamport0 + i * 32, 32);
        }

        for (size_t i=0; i < 255; i++) {
            Util::Hash256(lamportPk + 255 * 32 + i * 32, lamport1 + i * 32, 32);
        }
        Util::Hash256(outputLamportPk, lamportPk, 32 * 255 * 2);

        Util::SecFree(salt);
        Util::SecFree(ikm);
        Util::SecFree(notIkm);
        Util::SecFree(lamport0);
        Util::SecFree(lamport1);
        Util::SecFree(lamportPk);
    }

    static PrivateKey DeriveChildSk(PrivateKey& parentSk, uint32_t index) {
        uint8_t* lamportPk = Util::SecAlloc<uint8_t>(32);
        HDKeys::ParentSkToLamportPK(lamportPk, parentSk, index);
        PrivateKey child = PrivateKey::FromSeed(lamportPk, 32);
        Util::SecFree(lamportPk);
        return child;
    }
};
} // end namespace bls
#endif  // SRC_BLSHDKEYS_HPP_