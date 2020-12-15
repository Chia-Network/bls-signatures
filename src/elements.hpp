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

#ifndef SRC_BLSELEMENTS_HPP_
#define SRC_BLSELEMENTS_HPP_

extern "C" {
#include "relic.h"
}
#include "relic_conf.h"
#include "util.hpp"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include <utility>

namespace bls {
class G1Element;
class G2Element;
class GTElement;
class BNWrapper;

class G1Element {
public:
    static const size_t SIZE = 48;
    static G1Element FromBytes(const uint8_t *bytes);
    static G1Element FromByteVector(const std::vector<uint8_t> &bytevec);
    static G1Element FromNative(const g1_t *element);
    static G1Element FromMessage(
        const std::vector<uint8_t> &message,
        const uint8_t *dst,
        int dst_len);
    static G1Element Generator();
    static G1Element Infinity();  // infinity / unity

    void CheckValid() const;
    void ToNative(g1_t* output) const;
    G1Element Negate() const;
    GTElement Pair(const G2Element &b) const;
    uint32_t GetFingerprint() const;
    std::vector<uint8_t> Serialize() const;

    friend bool operator==(const G1Element &a, const G1Element &b);
    friend bool operator!=(const G1Element &a, const G1Element &b);
    friend std::ostream &operator<<(std::ostream &os, const G1Element &s);
    friend G1Element operator+(const G1Element &a, const G1Element &b);
    friend G1Element operator*(const G1Element &a, const bn_t &k);
    friend G1Element operator*(const bn_t &k, const G1Element &a);
    friend GTElement operator&(const G1Element &a, const G2Element &b);

private:
    g1_t p;
    G1Element() {
        g1_set_infty(p);
    }
};

class G2Element {
public:
    static const size_t SIZE = 96;
    static G2Element FromBytes(const uint8_t *data);
    static G2Element FromByteVector(const std::vector<uint8_t> &bytevec);
    static G2Element FromNative(const g2_t *element);
    static G2Element FromMessage(
        const std::vector<uint8_t> &message,
        const uint8_t *dst,
        int dst_len);
    static G2Element Generator();
    static G2Element Infinity();  // infinity/unity

    void CheckValid() const;
    void ToNative(g2_t* output) const;
    G2Element Negate() const;
    GTElement Pair(const G1Element &a) const;
    std::vector<uint8_t> Serialize() const;

    friend bool operator==(G2Element const &a, G2Element const &b);
    friend bool operator!=(G2Element const &a, G2Element const &b);
    friend std::ostream &operator<<(std::ostream &os, const G2Element &s);
    friend G2Element operator+(const G2Element &a, const G2Element &b);
    friend G2Element operator*(const G2Element &a, const bn_t &k);
    friend G2Element operator*(const bn_t &k, const G2Element &a);


private:
    g2_t q;
    G2Element() {
        g2_set_infty(q);
    }
};

class GTElement {
public:
    static const size_t SIZE = 384;
    static GTElement FromBytes(const uint8_t *bytes);
    static GTElement FromByteVector(const std::vector<uint8_t> &bytevec);
    static GTElement FromNative(const gt_t *element);
    static GTElement Unity();  // unity

    void Serialize(uint8_t *buffer) const;
    std::vector<uint8_t> Serialize() const;

    friend bool operator==(GTElement const &a, GTElement const &b);
    friend bool operator!=(GTElement const &a, GTElement const &b);
    friend std::ostream &operator<<(std::ostream &os, const GTElement &s);
    GTElement &operator=(const GTElement &rhs);

private:
    gt_t r;
    GTElement() {}
};

class BNWrapper {
public:
    bn_t *b = nullptr;

    BNWrapper() = default;

    BNWrapper(const BNWrapper& other)
    {
        b = Util::SecAlloc<bn_t>(1);
        bn_new(*b);
        bn_copy(*b, *(other.b));
    }

    BNWrapper(BNWrapper&& other)
        : b(std::exchange(other.b, nullptr))
    {}

    BNWrapper& operator=(const BNWrapper& other) &
    {
        if (&other == this) return *this;
        b = Util::SecAlloc<bn_t>(1);
        bn_new(*b);
        bn_copy(*b, *(other.b));
        return *this;
    }

    BNWrapper& operator=(BNWrapper&& other) &
    {
        if (&other == this) return *this;
        if (b) {
            bn_free(*b);
            Util::SecFree(b);
        }
        b = std::exchange(other.b, nullptr);
        return *this;
    }

    ~BNWrapper()
    {
        if(b != NULL) {
            bn_free(*b);
            Util::SecFree(b);
            b = NULL;
        }
    }

    static BNWrapper FromByteVector(std::vector<uint8_t> &bytes)
    {
        BNWrapper bnw;
        bnw.b = Util::SecAlloc<bn_t>(1);
        bn_new(*bnw.b);
        bn_zero(*bnw.b);
        bn_read_bin(*bnw.b, bytes.data(), bytes.size());
        return bnw;
    }

    friend std::ostream &operator<<(std::ostream &os, BNWrapper const &bnw)
    {
        int length = bn_size_bin(*bnw.b);
        uint8_t *data = new uint8_t[length];
        bn_write_bin(data, length, *bnw.b);
        std::string rst = Util::HexStr(data, length);
        delete[] data;
        return os << rst;
    }
};

}  // end namespace bls

#endif  // SRC_BLSELEMENTS_HPP_
