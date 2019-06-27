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
#include <set>
#include <algorithm>

#include "signature.hpp"
#include "bls.hpp"

using std::string;
namespace bls {

PrivateKey Threshold::Create(std::vector<PublicKey> &commitment,
        std::vector<PrivateKey> &secretFragments, size_t T, size_t N) {
    if (T < 1 || T > N) {
        throw std::string("Threshold parameter T must be between 1 and N");
    }
    PrivateKey k;
    k.AllocateKeyData();
    bn_t ord;
    bn_new(ord);
    g1_get_ord(ord);

    // poly = [random(1, ord-1), ...]
    // commitment = [g1 * poly[i], ...]
    g1_t g;
    bn_t *poly = new bn_t[T];
    for (int i = 0; i < T; ++i) {
        bn_new(poly[i]);
        bn_rand_mod(poly[i], ord);
        g1_mul_gen(g, poly[i]);
        commitment[i] = PublicKey::FromG1(&g);
    }

    bn_t frag, w, e;
    bn_new(frag);
    bn_new(w);
    bn_new(e);
    for (int x = 1; x <= N; ++x) {
        bn_zero(frag);
        // frag = sum_i (poly[i] * (x ** i % ord))
        for (int i = 0; i < T; ++i) {
            bn_set_dig(w, (dig_t) x);
            bn_set_dig(e, (dig_t) i);
            bn_mxp(w, w, e, ord);
            bn_mul(w, w, poly[i]);
            bn_mod(w, w, ord);
            bn_add(frag, frag, w);
            bn_mod(frag, frag, ord);
        }
        secretFragments[x-1] = PrivateKey::FromBN(frag);
    }

    bn_copy(*k.keydata, poly[0]);

    delete[] poly;

    return k;
}

InsecureSignature Threshold::SignWithCoefficient(PrivateKey sk, const uint8_t *msg,
        size_t len, size_t player, size_t *players, size_t T) {
    if (player == 0) {
        throw std::string("player must be a positive integer");
    }
    int index = std::distance(players,
        std::find(players, players + T, player));

    uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
    Util::Hash256(messageHash, msg, len);

    g2_t sig;
    g2_map(sig, messageHash, BLS::MESSAGE_HASH_LEN, 0);

    bn_t *coeffs = new bn_t[T];
    try {
        Threshold::LagrangeCoeffsAtZero(coeffs, players, T);
    } catch (const std::exception& e) {
        delete[] coeffs;
        throw e;
    }

    g2_mul(sig, sig, coeffs[index]);
    g2_mul(sig, sig, *sk.keydata);

    delete[] coeffs;

    return InsecureSignature::FromG2(&sig);
}

InsecureSignature Threshold::AggregateUnitSigs(
        std::vector<InsecureSignature> sigs, const uint8_t *msg, size_t len,
        size_t *players, size_t T) {
    uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
    Util::Hash256(messageHash, msg, len);

    bn_t *coeffs = new bn_t[T];
    Threshold::LagrangeCoeffsAtZero(coeffs, players, T);

    std::vector<InsecureSignature> powers;
    for (size_t i = 0; i < T; ++i) {
        powers.emplace_back(sigs[i].Exp(coeffs[i]));
    }

    InsecureSignature ret = InsecureSignature::Aggregate(powers);
    delete[] coeffs;
    return ret;
}

void Threshold::LagrangeCoeffsAtZero(bn_t *res, size_t *players, size_t T) {
    if (T <= 0) {
        throw std::invalid_argument("T must be a positive integer");
    }
    // n: the order of the curve
    bn_t denominator, n, u, weight, x;
    bn_new(denominator);
    bn_new(n);
    bn_new(weight);
    bn_new(x);
    g1_get_ord(n);

    bn_zero(denominator);
    for (int j = 0; j < T; ++j) {
        if (players[j] <= 0) {
            throw std::invalid_argument("Player index must be positive");
        }
        // weight = (prod (X[j] - X[i])) ** -1
        bn_set_dig(weight, (dig_t) 1);
        for (int i = 0; i < T; ++i) if (i != j) {
            if (players[j] > players[i]) {
                bn_set_dig(x, (dig_t)(players[j] - players[i]));
            } else if (players[i] > players[j]){
                bn_set_dig(x, (dig_t)(players[i] - players[j]));
                bn_sub(x, n, x);
            } else {
                throw std::invalid_argument("Must not have duplicate player indices");
            }
            bn_mul(weight, weight, x);
            bn_mod(weight, weight, n);
        }
        // weight = weight ** -1
        // x = (-players[j]) ** -1
        if (bn_is_zero(weight)) {
            throw std::invalid_argument("Player indices can't be equiv. mod group order");
        }
        fp_inv_exgcd_bn(weight, weight, n);
        bn_set_dig(x, (dig_t) players[j]);
        bn_sub(x, n, x);
        fp_inv_exgcd_bn(x, x, n);

        bn_mul(weight, weight, x);
        bn_mod(weight, weight, n);
        bn_copy(res[j], weight);

        bn_add(denominator, denominator, weight);
    }

    fp_inv_exgcd_bn(denominator, denominator, n);
    for (int j = 0; j < T; ++j) {
        bn_mul(res[j], res[j], denominator);
        bn_mod(res[j], res[j], n);
    }
}

void Threshold::InterpolateAtZero(bn_t res, size_t *X, bn_t *Y, size_t T) {
    if (T <= 0) {
        throw std::invalid_argument("T must be a positive integer");
    }

    bn_zero(res);
    bn_t n;
    bn_new(n);
    g1_get_ord(n);

    bn_t *coeffs = new bn_t[T];
    LagrangeCoeffsAtZero(coeffs, X, T);
    for (int i = 0; i < T; ++i) {
        // res += coeffs[i] * Y[i]
        bn_mul(coeffs[i], coeffs[i], Y[i]);
        bn_mod(coeffs[i], coeffs[i], n);
        bn_add(res, res, coeffs[i]);
        bn_mod(res, res, n);
    }
}

bool Threshold::VerifySecretFragment(size_t player, PrivateKey secretFragment, std::vector<PublicKey> const& commitment, size_t T) {
    if (T <= 0) {
        throw std::invalid_argument("T must be a positive integer");
    } else if (player <= 0) {
        throw std::invalid_argument("Player index must be positive");
    }

    g1_t rhs, t;
    bn_t x, n, e;
    bn_new(x);
    bn_new(n);
    bn_new(e);
    g1_get_ord(n);

    // rhs = sum commitment[i] ** (player ** i)
    std::vector<PublicKey> expKeys;
    expKeys.reserve(T);
    for (size_t i = 0; i < T; i++) {
        bn_set_dig(x, (dig_t) player);
        bn_set_dig(e, (dig_t) i);
        bn_mxp(x, x, e, n);
        expKeys.emplace_back(commitment[i].Exp(x));
    }

    return (secretFragment.GetPublicKey() ==
            PublicKey::AggregateInsecure(expKeys));
}

} // end namespace bls
