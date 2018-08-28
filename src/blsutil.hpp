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

#if BLSALLOC == sodium
namespace libsodium {
    #include "sodium/utils.h"
    #include "sodium/core.h"
}
#endif

namespace relic {
    #include "relic.h"
    #include "relic_test.h"
}

class BLSUtil {
 public:
    static void Hash256(uint8_t* output, const uint8_t* message,
                        size_t messageLen) {
        relic::md_map_sh256(output, message, messageLen);
    }

    struct BytesCompare32 {
        bool operator() (const uint8_t* lhs, const uint8_t* rhs) const {
            for (size_t i = 0; i < 32; i++) {
                if (lhs[i] < rhs[i]) return true;
                if (lhs[i] > rhs[i]) return false;
            }
            return false;
        }
    };

    struct BytesCompare80 {
        bool operator() (const uint8_t* lhs, const uint8_t* rhs) const {
            for (size_t i = 0; i < 80; i++) {
                if (lhs[i] < rhs[i]) return true;
                if (lhs[i] > rhs[i]) return false;
            }
            return false;
        }
    };

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
#if BLSALLOC
        return static_cast<T*>(libsodium::sodium_malloc
                (sizeof(T) * numTs));
#else
        return static_cast<T*>(malloc(sizeof(T) * numTs));
#endif
    }

    /*
     * Frees memory allocated using SecAlloc.
     */
    static void SecFree(void* ptr) {
#if BLSALLOC
        libsodium::sodium_free(ptr);
#else
        free(ptr);
#endif
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
};

#endif  // SRC_BLSUTIL_HPP_
