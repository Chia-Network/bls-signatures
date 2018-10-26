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

void ThresholdUtil::lagrangeCoeffsAtZero(bn_t *res, int *players, int T) {
    if (T <= 0) {
        throw std::string("T must be a positive integer");
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
        // weight = (prod (X[j] - X[i])) ** -1
        bn_set_dig(weight, (dig_t) 1);
        for (int i = 0; i < T; ++i) if (i != j) {
            if (players[j] > players[i]) {
                bn_set_dig(x, (dig_t)(players[j] - players[i]));
            } else if (players[i] > players[j]){
                bn_set_dig(x, (dig_t)(players[i] - players[j]));
                bn_sub(x, n, x);
            } else {
                throw std::string("Must not have duplicate player indices");
            }
            bn_mul(weight, weight, x);
            bn_mod(weight, weight, n);
        }
        // weight = weight ** -1
        // x = (-players[j]) ** -1
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

void ThresholdUtil::interpolateAtZero(bn_t res, int *X, bn_t *Y, int T) {
    if (T <= 0) {
        throw std::string("T must be a positive integer");
    }

    bn_zero(res);
    bn_t n;
    bn_new(n);
    g1_get_ord(n);

    bn_t *coeffs = new bn_t[T];
    lagrangeCoeffsAtZero(coeffs, X, T);
    for (int i = 0; i < T; ++i) {
        // res += coeffs[i] * Y[i]
        bn_mul(coeffs[i], coeffs[i], Y[i]);
        bn_mod(coeffs[i], coeffs[i], n);
        bn_add(res, res, coeffs[i]);
        bn_mod(res, res, n);
    }
}

bool ThresholdUtil::verifySecretFragment(int player, bn_t secretFragment, g1_t *commitment, int T) {
    if (T <= 0) {
        throw std::string("T must be a positive integer");
    } else if (bn_is_zero(secretFragment) == 1) {
        throw std::string("secretFragment must be non-zero");
    } else if (player <= 0) {
        throw std::string("player index must be positive");
    }

    g1_t g1, lhs, rhs, t;
    g1_null(g1);
    g1_null(lhs);
    g1_null(rhs);
    g1_null(t);
    g1_new(g1);
    g1_new(lhs);
    g1_new(rhs);
    g1_new(t);

    bn_t x, n, e;
    bn_new(x);
    bn_new(n);
    bn_new(e);
    g1_get_ord(n);

    // lhs = g1 * secretFragment
    g1_get_gen(g1);
    g1_copy(lhs, g1);
    g1_mul(lhs, lhs, secretFragment);

    // rhs = sum commitment[i] * (player ** i)
    g1_copy(rhs, commitment[0]);
    for (int i = 1; i < T; ++i) {
        g1_copy(t, commitment[i]);
        bn_set_dig(x, (dig_t) player);
        bn_set_dig(e, (dig_t) i);
        bn_mxp(x, x, e, n);
        g1_mul(t, t, x);
        g1_add(rhs, rhs, t);
    }

    return (g1_cmp(lhs, rhs) == CMP_EQ);
}
} // end namespace bls
