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

#ifndef SRC_BLSHDCKD_HPP_
#define SRC_BLSHDCKD_HPP_

#include "relic.h"
#include "relic_conf.h"
#include "util.hpp"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

using std::vector;

namespace bls {
class HDCKD;  // Static functions for HDKey Child Key Derivation

class HDCKD {
public:
    // Need to specify Minimal Pubkey Size scheme because of G1 use
    static PrivateKey sk_to_sk_MPS(
        PrivateKey& sk,
        vector<uint8_t> destination,
        bool hardened = false)
    {
        size_t keyLen =
            hardened ? PrivateKey::PRIVATE_KEY_SIZE : G1Element::SIZE;
        size_t inputLen = keyLen + destination.size();
        uint8_t* shaInput = Util::SecAlloc<uint8_t>(inputLen);
        if (hardened) {
            sk.Serialize(shaInput);
        } else {
            sk.GetG1Element().Serialize(shaInput);
        }
        memcpy(shaInput + keyLen, destination.data(), destination.size());

        uint8_t* hashOut =
            Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
        md_map_sh256(hashOut, shaInput, inputLen);

        // Check for failure
        bool failed = false;

        // try {
        //     PrivateKey newSk = PrivateKey::FromBytes(hashOut, false);
        // } catch (...) {
        //     failed = true;
        // }

        PrivateKey newSk = PrivateKey::FromBytes(hashOut, false);
        newSk = PrivateKey::Aggregate({sk, newSk});

        // if (newSk.IsZero()) {
        //     failed = true;
        // }

        /*
        Util::SecFree(shaInput);
        Util::SecFree(hashOut);

        if (failed) {
            for (int i = (int)destination.size() - 1; i >= 0; --i) {
                destination[i]++;
                if (destination[i] != 0)
                    break;
            }
            return sk_to_sk_MPS(sk, destination, hardened);
        }
        */

        return newSk;
    }

    static G1Element g1_to_g1(G1Element& pk, vector<uint8_t> destination)
    {
        uint8_t* shaInput =
            Util::SecAlloc<uint8_t>(G1Element::SIZE + destination.size());

        pk.Serialize(shaInput);
        memcpy(
            shaInput + G1Element::SIZE, destination.data(), destination.size());
        G1Element point = G1Element();
        uint8_t* hashOut =
            Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
        md_map_sh256(hashOut, shaInput, G1Element::SIZE + destination.size());

        bn_t nonce, ord;
        bn_new(nonce);
        bn_read_bin(nonce, hashOut, PrivateKey::PRIVATE_KEY_SIZE);
        bn_new(ord);
        g1_get_ord(ord);
        bn_mod_basic(nonce, nonce, ord);

        bool failed = false;
        if (bn_cmp(nonce, ord) > 0) {
            failed = true;
        }
        G1Element ans = G1Element::FromBN(nonce);
        if (ans == G1Element()) {
            failed = true;
        }

        Util::SecFree(shaInput);
        Util::SecFree(hashOut);

        if (failed) {
            for (int i = (int)destination.size() - 1; i >= 0; --i) {
                destination[i]++;
                if (destination[i] != 0)
                    break;
            }
            return g1_to_g1(pk, destination);
        }
        return ans;
    }
};

}  // end namespace bls

#endif  // SRC_BLSELEMENTS_HPP_
