/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2012 RELIC Authors
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
 * Implementation of low-level prime field modular reduction.
 *
 * @version $Id: relic_fp_add_low.c 88 2009-09-06 21:27:19Z dfaranha $
 * @ingroup fp
 */

#include "relic_fp_low.h"

#include "macro.s"

.data

p0: .quad 0xAAA00001800002AB
p1: .quad 0xA6C589556B2AA956
p2: .quad 0xB3DB9994ACE86D1B
p3: .quad 0x4BD93954FCB314B8
p4: .quad 0x3F665E3A5B1D5623
p5: .quad 0xA00E0F95B4920300
p6: .quad 0x555955557955572A
p7: .quad 0x0000000000000055
u0: .quad 0x4B3EF8137F4017FD

.text

.global fp_rdcn_low

/*
 * Function: fp_rdcn_low
 * Inputs: rdi = c, rsi = a
 * Output: rax
 */
fp_rdcn_low:
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push 	%rbx
	push	%rbp
	leaq 	p0, %rbx

	FP_RDCN_LOW %rdi, %r8, %r9, %r10, %rsi, %rbx

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
