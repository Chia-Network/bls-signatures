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

#ifndef SRC_BLSTHRESHOLD_HPP_
#define SRC_BLSTHRESHOLD_HPP_

#include <iostream>
#include <vector>

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "util.hpp"

namespace bls {
/**
 * Utility functions for threshold signatures.
 */
class ThresholdUtil {
public:
    /**
     * Returns lagrange coefficients of a polynomial evaluated at zero.
     * If we have T points (players[i], P(players[i])), it interpolates
     * to a degree T-1 polynomial P.  The returned coefficients are
     * such that P(0) = sum_i res[i] * P(players[i]).
     *
     * @param[out] res			- the lagrange coefficients.
     * @param[in] players		- the indices of each player.
     * @param[in] T             - the number of points.
     */
    static void lagrangeCoeffsAtZero(bn_t *res, int *players, int T);

    /**
     * The points (X[i], Y[i]) for i = 0...T-1 interpolate into P,
     * a degree T-1 polynomial.  Returns P(0).
     *
     * @param[out] res          - the value P(0).
     * @param[in] X             - the X coordinates,
     * @param[in] Y             - the Y coordinates.
     * @param[in] T             - the number of points.
     */
    static void interpolateAtZero(bn_t res, int *X, bn_t *Y, int T);

    /**
     * Return true iff the secretFragment from the given player
     * matches their given commitment to a polynomial.
     *
     * @param[in] player       - the index of the player giving the fragment.
     * @param[in] secretFragment - the fragment, a number in [1, n)
     * @param[in] commitment - the player's claim commitment[i] = g1 * [x^i]P
     * @param[in] T - the threshold parameter and number of points.
     * @return true if the fragment is verified, else false.
     */
    static bool verifySecretFragment(int player, bn_t secretFragment,
        g1_t *commitment, int T);
};
} // end namespace bls

#endif  // SRC_BLSTHRESHOLD_HPP_
