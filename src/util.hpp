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

#ifndef SRC_BLSUTIL_HPP_
#define SRC_BLSUTIL_HPP_

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstdlib>

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "relic.h"
#include "relic_test.h"

namespace bls {

class BLS;

class Util {
 public:
    typedef void *(*SecureAllocCallback)(size_t);
    typedef void (*SecureFreeCallback)(void*);
 public:
    static void Hash256(uint8_t* output, const uint8_t* message,
                        size_t messageLen) {
        md_map_sh256(output, message, messageLen);
    }

    template<size_t S>
    struct BytesCompare {
        bool operator() (const uint8_t* lhs, const uint8_t* rhs) const {
            for (size_t i = 0; i < S; i++) {
                if (lhs[i] < rhs[i]) return true;
                if (lhs[i] > rhs[i]) return false;
            }
            return false;
        }
    };
    typedef struct BytesCompare<32> BytesCompare32;
    typedef struct BytesCompare<80> BytesCompare80;

    static std::string HexStr(const uint8_t* data, size_t len) {
        std::stringstream s;
        s << std::hex;
        for (int i=0; i < len; ++i)
            s << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        return s.str();
    }

    /*
     * Securely allocates a portion of memory, using libsodium. This prevents
     * paging to disk, and zeroes out the memory when it's freed.
     */
    template<class T>
    static T* SecAlloc(size_t numTs) {
        return static_cast<T*>(secureAllocCallback(sizeof(T) * numTs));
    }

    /*
     * Frees memory allocated using SecAlloc.
     */
    static void SecFree(void* ptr) {
        secureFreeCallback(ptr);
    }

    /*
     * Converts a 32 bit int to bytes.
     */
    static void IntToFourBytes(uint8_t* result,
                               const uint32_t input) {
        for (size_t i = 0; i < 4; i++) {
            result[3 - i] = (input >> (i * 8));
        }
    }

    /*
     * Converts a byte array to a 32 bit int.
     */
    static uint32_t FourBytesToInt(const uint8_t* bytes) {
        uint32_t sum = 0;
        for (size_t i = 0; i < 4; i++) {
            uint32_t addend = bytes[i] << (8 * (3 - i));
            sum += addend;
        }
        return sum;
    }

 private:
    friend class BLS;
    static SecureAllocCallback secureAllocCallback;
    static SecureFreeCallback secureFreeCallback;
};
} // end namespace bls

#include <mcl/bn_c384_256.h>
#include <assert.h>
namespace mcl {

inline void byteSwap(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n/2; i++) {
        std::swap(buf[i], buf[n - 1 - i]);
    }
}

inline void conv(mclBnFr *out, const bn_t *in)
{
    assert(in[0]->sign == 0);
    const int n = in[0]->used;
    int ret = mclBnFr_setLittleEndianMod(out, in[0]->dp, n * 8);
    assert(ret == 0);
}

inline void conv(bn_t *out, const mclBnFr *in)
{
    uint8_t buf[256];
    size_t n = mclBnFr_getLittleEndian(buf, sizeof(buf), in);
    assert(n > 0);
    byteSwap(buf, n);
    bn_read_bin(*out, buf, n);
}

/*
    g1_t {
        fp_st x, y, z;
        int norm;
    };
    fp_st = mclBnFp
*/
inline void conv(mclBnG1 *out, const g1_t *in)
{
    memcpy(&out->d[MCLBN_FP_UNIT_SIZE * 0], &in[0]->x, MCLBN_FP_UNIT_SIZE * 8);
    memcpy(&out->d[MCLBN_FP_UNIT_SIZE * 1], &in[0]->y, MCLBN_FP_UNIT_SIZE * 8);
    memcpy(&out->d[MCLBN_FP_UNIT_SIZE * 2], &in[0]->z, MCLBN_FP_UNIT_SIZE * 8);
}

inline void conv(g1_t *out, const mclBnG1 *in)
{
    memcpy(&out[0]->x, &in->d[MCLBN_FP_UNIT_SIZE * 0], MCLBN_FP_UNIT_SIZE * 8);
    memcpy(&out[0]->y, &in->d[MCLBN_FP_UNIT_SIZE * 1], MCLBN_FP_UNIT_SIZE * 8);
    memcpy(&out[0]->z, &in->d[MCLBN_FP_UNIT_SIZE * 2], MCLBN_FP_UNIT_SIZE * 8);
    out[0]->norm = 0;
}

inline void conv(mclBnG2 *out, const g2_t *in)
{
    memcpy(&out->d[MCLBN_FP_UNIT_SIZE * 0], &in[0]->x, MCLBN_FP_UNIT_SIZE * 8 * 2);
    memcpy(&out->d[MCLBN_FP_UNIT_SIZE * 2], &in[0]->y, MCLBN_FP_UNIT_SIZE * 8 * 2);
    memcpy(&out->d[MCLBN_FP_UNIT_SIZE * 4], &in[0]->z, MCLBN_FP_UNIT_SIZE * 8 * 2);
}

inline void conv(g2_t *out, const mclBnG2 *in)
{
    memcpy(&out[0]->x, &in->d[MCLBN_FP_UNIT_SIZE * 0], MCLBN_FP_UNIT_SIZE * 8 * 2);
    memcpy(&out[0]->y, &in->d[MCLBN_FP_UNIT_SIZE * 2], MCLBN_FP_UNIT_SIZE * 8 * 2);
    memcpy(&out[0]->z, &in->d[MCLBN_FP_UNIT_SIZE * 4], MCLBN_FP_UNIT_SIZE * 8 * 2);
    out[0]->norm = 0;
}

} // mcl

#endif  // SRC_BLSUTIL_HPP_
