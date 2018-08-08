/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2017 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of squaring in a cubic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_CBC == BASIC || !defined(STRIP)

void fp3_sqr_basic(fp3_t c, fp3_t a) {
	dv_t t0, t1, t2, t3, t4, t5;

	dv_null(t0);
	dv_null(t1);
	dv_null(t2);
	dv_null(t3);
	dv_null(t4);
	dv_null(t5);

	TRY {
		dv_new(t0);
		dv_new(t1);
		dv_new(t2);
		dv_new(t3);
		dv_new(t4);
		dv_new(t5);

		/* t0 = a_0^2. */
		fp_sqrn_low(t0, a[0]);

		/* t1 = 2 * a_1 * a_2. */
		fp_dbl(t2, a[1]);
		fp_muln_low(t1, t2, a[2]);

		/* t2 = a_2^2. */
		fp_sqrn_low(t2, a[2]);

		/* t3 = (a_0 + a_2 + a_1)^2, t4 = (a_0 + a_2 - a_1)^2. */
		fp_add(t3, a[0], a[2]);
		fp_add(t4, t3, a[1]);
		fp_sub(t5, t3, a[1]);
		fp_sqrn_low(t3, t4);
		fp_sqrn_low(t4, t5);

		/* t4 = (t4 + t3)/2. */
		fp_addd_low(t4, t4, t3);
		fp_hlvd_low(t4, t4);

		/* t3 = t3 - t4 - t1. */
		fp_addc_low(t5, t1, t4);
		fp_subc_low(t3, t3, t5);

		/* c_2 = t4 - t0 - t2. */
		fp_addc_low(t5, t0, t2);
		fp_subc_low(t4, t4, t5);
		fp_rdc(c[2], t4);

		/* c_0 = t0 + t1 * B. */
		fp_subc_low(t0, t0, t1);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_subc_low(t0, t0, t1);
		}
		fp_rdc(c[0], t0);

		/* c_1 = t3 + t2 * B. */
		fp_subc_low(t3, t3, t2);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_subc_low(t3, t3, t2);
		}
		fp_rdc(c[1], t3);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		dv_free(t0);
		dv_free(t1);
		dv_free(t2);
		dv_free(t3);
		dv_free(t4);
		dv_free(t5);
	}
}

#endif

#if FPX_CBC == INTEG || !defined(STRIP)

void fp3_sqr_integ(fp3_t c, fp3_t a) {
	fp3_sqrm_low(c, a);
}

#endif
