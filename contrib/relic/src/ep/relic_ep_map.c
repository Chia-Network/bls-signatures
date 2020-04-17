/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of hashing to a prime elliptic curve.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#ifdef EP_CTMAP

/**
 * Evaluate a polynomial represented by its coefficients over a using Horner's
 * rule. Might promove to an API if needed elsewhere in the future.
 *
 * @param[out] c		- the result.
 * @param[in] a			- the input value.
 * @param[in] coeffs	- the vector of coefficients in the polynomial.
 * @param[in] deg 		- the degree of the polynomial.
 */
TMPL_MAP_HORNER(fp, fp_st)

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
TMPL_MAP_ISOGENY_MAP()
#endif /* EP_CTMAP */

/**
 * Simplified SWU mapping from Section 4 of
 * "Fast and simple constant-time hashing to the BLS12-381 Elliptic Curve"
 */
#define EP_MAP_COPY_COND(O, I, C) dv_copy_cond(O, I, RLC_FP_DIGS, C)
TMPL_MAP_SSWU(,dig_t,EP_MAP_COPY_COND)

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
TMPL_MAP_SVDW(,dig_t,EP_MAP_COPY_COND)
#undef EP_MAP_COPY_COND

/* caution: this function overwrites k, which it uses as an auxiliary variable */
static inline int fp_sgn0(const fp_t t, bn_t k) {
	fp_prime_back(k, t);
	return bn_get_bit(k, 0);
}


/**
 * Based on the rust implementation of pairings, zkcrypto/pairing.
 * The algorithm is Shallue–van de Woestijne encoding from
 * Section 3 of "Indifferentiable Hashing to Barreto–Naehrig Curves"
 * from Fouque-Tibouchi: <https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf>
 */
void ep_sw_encode(ep_t p, fp_t t) {
	if (fp_is_zero(t)) {
		ep_set_infty(p);
		return;
	}
	fp_t nt; // Negative t
	fp_t w;
	fp_t s_n3;
	fp_t s_n3m1o2;
	fp_t two_inv;
	fp_t x1;
	fp_t x2;
	fp_t x3;
	fp_t rhs;
	fp_t ny;

	fp_new(nt);
	fp_new(w);
	fp_new(s_n3);
	fp_new(s_n3m1o2);
	fp_new(two_inv);
	fp_new(x1);
	fp_new(x2);
	fp_new(x3);
	fp_new(rhs);
	fp_new(ny);

	fp_neg(nt, t);

	uint8_t buf0[RLC_FP_BYTES];
	uint8_t buf1[RLC_FP_BYTES];
	fp_write_bin(buf0, RLC_FP_BYTES, t);
	fp_write_bin(buf1, RLC_FP_BYTES, nt);
	int parity = (memcmp(buf0, buf1, RLC_FP_BYTES) > 0);

	// w = t^2 + b + 1
	fp_mul(w, t, t);
	fp_add(w, w, ep_curve_get_b());
	fp_add_dig(w, w, 1);

	if (fp_is_zero(w)) {
		// Returns generator
		ep_curve_get_gen(p);
		return;
	}

	// sqrt(-3)
	fp_set_dig(s_n3, 3);
	fp_neg(s_n3, s_n3);
	fp_srt(s_n3, s_n3);

	// (sqrt(-3) - 1) / 2
	fp_copy(s_n3m1o2, s_n3);
	fp_sub_dig(s_n3m1o2, s_n3m1o2, 1);
	fp_set_dig(two_inv, 2);
	fp_inv(two_inv, two_inv);
	fp_mul(s_n3m1o2, s_n3m1o2, two_inv);

	fp_inv(w, w);
	fp_mul(w, w, s_n3);
	fp_mul(w, w, t);

	// x1 = -wt + sqrt(-3)
	fp_neg(x1, w);
	fp_mul(x1, x1, t);
	fp_add(x1, x1, s_n3m1o2);

	// x2 = -x1 - 1
	fp_neg(x2, x1);
	fp_sub_dig(x2, x2, 1);

	// x3 = 1/w^2 + 1
	fp_mul(x3, w, w);
	fp_inv(x3, x3);
	fp_add_dig(x3, x3, 1);

	fp_zero(p->y);
	fp_set_dig(p->z, 1);

	fp_copy(p->x, x1);
	ep_rhs(rhs, p);
	int Xx1 = fp_srt(p->y, rhs) ? 1 : -1;
	fp_copy(p->x, x2);
	ep_rhs(rhs, p);
	int Xx2 = fp_srt(p->y, rhs) ? 1 : -1;
	int index = ((((Xx1 - 1) * Xx2) % 3) + 3) % 3;

	if (index == 0) {
		fp_copy(p->x, x1);
	} else if (index == 1) {
		fp_copy(p->x, x2);
	} else if (index == 2) {
		fp_copy(p->x, x3);
	}
	ep_rhs(rhs, p);
	fp_srt(p->y, rhs);

	p->norm = 1;
	fp_neg(ny, p->y);

	fp_write_bin(buf0, RLC_FP_BYTES, p->y);
	fp_write_bin(buf1, RLC_FP_BYTES, ny);
	if ((memcmp(buf0, buf1, RLC_FP_BYTES) > 0) != parity) {
		ep_neg(p, p);
	}
	fp_free(nt);
	fp_free(w);
	fp_free(s_n3);
	fp_free(s_n3m1o2);
	fp_free(two_inv);
	fp_free(x1);
	fp_free(x2);
	fp_free(x3);
	fp_free(rhs);
	fp_free(ny);
}


void ep_map_impl(ep_t p, const uint8_t *msg, int len, const uint8_t *dst, int dst_len) {
	bn_t k;
	fp_t t;
	ep_t q;
	int neg;
	/* enough space for two field elements plus extra bytes for uniformity */
	const int len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *pseudo_random_bytes = RLC_ALLOCA(uint8_t, 4 * len_per_elm);

	bn_null(k);
	fp_null(t);
	ep_null(q);

	TRY {
		bn_new(k);
		fp_new(t);
		ep_new(q);

		/* figure out which hash function to use */
		const int abNeq0 = (ep_curve_opt_a() != RLC_ZERO) && (ep_curve_opt_b() != RLC_ZERO);
		void (*const map_fn)(ep_t, fp_t) = (ep_curve_is_ctmap() || abNeq0) ? ep_map_sswu : ep_map_svdw;

		/* for hash_to_field, need to hash to a pseudorandom string */
		/* XXX(rsw) the below assumes that we want to use MD_MAP for hashing.
		 *          Consider making the hash function a per-curve option!
		 */
		md_xmd(pseudo_random_bytes, 2 * len_per_elm, msg, len, dst, dst_len);

#define EP_MAP_CONVERT_BYTES(IDX)                                              \
	do {                                                                       \
		bn_read_bin(k, pseudo_random_bytes + IDX * len_per_elm, len_per_elm);  \
		fp_prime_conv(t, k);                                                   \
	} while (0)

#define EP_MAP_APPLY_MAP(PT)                                                   \
	do {                                                                       \
		/* check sign of t */                                                  \
		neg = fp_sgn0(t, k);                                                   \
		/* convert */                                                          \
		map_fn(PT, t);                                                         \
		/* compare sign of y and sign of t; fix if necessary */                \
		neg = neg != fp_sgn0(PT->y, k);                                        \
		fp_neg(t, PT->y);                                                      \
		dv_copy_cond(PT->y, t, RLC_FP_DIGS, neg);                              \
	} while (0)

		/* first map invocation */
		EP_MAP_CONVERT_BYTES(0);
		EP_MAP_APPLY_MAP(p);
		TMPL_MAP_CALL_ISOMAP(,p);

		/* second map invocation */
		EP_MAP_CONVERT_BYTES(1);
		EP_MAP_APPLY_MAP(q);
		TMPL_MAP_CALL_ISOMAP(,q);

		/* XXX(rsw) could add p and q and then apply isomap,
		 * but need ep_add to support addition on isogeny curves */

#undef EP_MAP_CONVERT_BYTES
#undef EP_MAP_APPLY_MAP

		/* sum the result */
		ep_add(p, p, q);
		ep_norm(p, p);

		/* clear cofactor */
		switch (ep_curve_is_pairf()) {
			case EP_BN:
				/* h = 1 */
				break;
			case EP_B12:
				/* multiply by 1-x (x the BLS parameter) to get the correct group. */
				/* XXX(rsw) is this guaranteed to work? It could fail if one
				 *          of the prime-squared subgroups is cyclic, but
				 *          maybe there's an argument that this is never the case...
				 */
				fp_prime_get_par(k);
				bn_neg(k, k);
				bn_add_dig(k, k, 1);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(p, p, k->dp[0]);
				} else {
					ep_mul(p, p, k);
				}
				break;
			default:
				/* multiply by cofactor to get the correct group. */
				ep_curve_get_cof(k);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(p, p, k->dp[0]);
				} else {
					ep_mul_basic(p, p, k);
				}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(k);
		fp_free(t);
		ep_free(q);
		RLC_FREE(pseudo_random_bytes);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

// void ep_map(ep_t p, const uint8_t *msg, int len) {
// 	ep_map_impl(p, msg, len, (const uint8_t *)"RELIC", 5);
// }

void ep_map(ep_t p, const uint8_t *msg, int len) {
	bn_t t0;
	bn_t t1;
	fp_t t0p;
	fp_t t1p;
	ep_t p0;
	ep_t p1;
	bn_t k;

	TRY {
		uint8_t input[RLC_MD_LEN + 5];
		md_map(input, msg, len);

		// b"G1_0"
		input[RLC_MD_LEN + 0] = 0x47;
		input[RLC_MD_LEN + 1] = 0x31;
		input[RLC_MD_LEN + 2] = 0x5f;
		input[RLC_MD_LEN + 3] = 0x30;

		fp_new(t0p);
		fp_new(t1p);
		bn_new(t0);
		bn_new(t1);
		ep_new(p0);
		ep_new(p1);
		bn_new(k);

		uint8_t t0Bytes[RLC_MD_LEN * 2];
		uint8_t t1Bytes[RLC_MD_LEN * 2];

		input[RLC_MD_LEN + 4] = 0;
		md_map(t0Bytes, input, RLC_MD_LEN + 5);
		input[RLC_MD_LEN + 4] = 1;
		md_map(t0Bytes + RLC_MD_LEN, input, RLC_MD_LEN + 5);

		// b"G1_1"
		input[RLC_MD_LEN + 3] = 0x31;

		input[RLC_MD_LEN + 4] = 0;
		md_map(t1Bytes, input, RLC_MD_LEN + 5);
		input[RLC_MD_LEN + 4] = 1;
		md_map(t1Bytes + RLC_MD_LEN, input, RLC_MD_LEN + 5);

		bn_read_bin(t0, t0Bytes, RLC_MD_LEN * 2);
		bn_read_bin(t1, t1Bytes, RLC_MD_LEN * 2);

		fp_prime_conv(t0p, t0);
		fp_prime_conv(t1p, t1);

		ep_sw_encode(p0, t0p);
		ep_sw_encode(p1, t1p);
		ep_add(p0, p0, p1);

		/* Now, multiply by cofactor to get the correct group. */
		ep_curve_get_cof(k);
		if (bn_bits(k) < RLC_DIG) {
			ep_mul_dig(p, p0, k->dp[0]);
		} else {
			ep_mul(p, p0, k);
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(k);
		ep_free(p0);
		ep_free(p1);
		fp_free(t0p);
		fp_free(t1p);
		bn_free(t0);
		bn_free(t1);
	}
}

