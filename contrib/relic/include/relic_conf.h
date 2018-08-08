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
 * Project configuration.
 *
 * @version $Id: relic_conf.h.in 45 2009-07-04 23:45:48Z dfaranha $
 * @ingroup relic
 */

#ifndef RELIC_CONF_H
#define RELIC_CONF_H

/** Project version. */
#define RELIC_VERSION "0.4.1"

/** Debugging support. */
/* #undef DEBUG */
/** Profiling support. */
/* #undef PROFL */
/** Error handling support. */
/* #undef CHECK */
/** Verbose error messages. */
/* #undef VERBS */
/** Trace support. */
/* #undef TRACE */
/** Build with overhead estimation. */
/* #undef OVERH */
/** Build documentation. */
#define DOCUM
/** Build only the selected algorithms. */
/* #undef STRIP */
/** Build with printing disabled. */
/* #undef QUIET */
/** Build with colored output. */
#define COLOR
/** Build with big-endian support. */
/* #undef BIGED */
/** Build shared library. */
/* #undef SHLIB */
/** Build static library. */
#define STLIB

/** Number of times each test is ran. */
#define TESTS    100
/** Number of times each benchmark is ran. */
#define BENCH    100

/** Number of available cores. */
#define CORES    1

/** Atmel AVR ATMega128 8-bit architecture. */
#define AVR      1
/** MSP430 16-bit architecture. */
#define MSP      2
/** ARM 32-bit architecture. */
#define ARM      3
/** Intel x86-compatible 32-bit architecture. */
#define X86      4
/** AMD64-compatible 64-bit architecture. */
#define X64      5
/** Architecture. */
#define ARCH	 X64

/** Size of word in this architecture. */
#define WORD     64

/** Byte boundary to align digit vectors. */
#define ALIGN    1

/** Build multiple precision integer module. */
#define WITH_BN
/** Build prime field module. */
#define WITH_FP
/** Build prime field extension module. */
#define WITH_FPX
/** Build binary field module. */
#define WITH_FB
/** Build prime elliptic curve module. */
#define WITH_EP
/** Build prime field extension elliptic curve module. */
#define WITH_EPX
/** Build binary elliptic curve module. */
#define WITH_EB
/** Build elliptic Edwards curve module. */
#define WITH_ED
/** Build elliptic curve cryptography module. */
#define WITH_EC
/** Build pairings over prime curves module. */
#define WITH_PP
/** Build pairing-based cryptography module. */
#define WITH_PC
/** Build block ciphers. */
#define WITH_BC
/** Build hash functions. */
#define WITH_MD
/** Build cryptographic protocols. */
#define WITH_CP

/** Easy C-only backend. */
#define EASY	 1
/** GMP backend. */
#define GMP      2
/** Arithmetic backend. */
#define ARITH    EASY

/** Required precision in bits. */
#define BN_PRECI 1024
/** A multiple precision integer can store w words. */
#define SINGLE	 0
/** A multiple precision integer can store the result of an addition. */
#define CARRY	 1
/** A multiple precision integer can store the result of a multiplication. */
#define DOUBLE	 2
/** Effective size of a multiple precision integer. */
#define BN_MAGNI DOUBLE
/** Number of Karatsuba steps. */
#define BN_KARAT 0

/** Schoolbook multiplication. */
#define BASIC    1
/** Comba multiplication. */
#define COMBA    2
/** Chosen multiple precision multiplication method. */
#define BN_MUL   COMBA

/** Schoolbook squaring. */
#define BASIC    1
/** Comba squaring. */
#define COMBA    2
/** Reuse multiplication for squaring. */
#define MULTP    4
/** Chosen multiple precision multiplication method. */
#define BN_SQR   COMBA

/** Division modular reduction. */
#define BASIC    1
/** Barrett modular reduction. */
#define BARRT    2
/** Montgomery modular reduction. */
#define MONTY    3
/** Pseudo-Mersenne modular reduction. */
#define PMERS    4
/** Chosen multiple precision modular reduction method. */
#define BN_MOD   MONTY

/** Binary modular exponentiation. */
#define BASIC    1
/** Sliding window modular exponentiation. */
#define SLIDE    2
/** Montgomery powering ladder. */
#define MONTY    3
/** Chosen multiple precision modular exponentiation method. */
#define BN_MXP   SLIDE

/** Basic Euclidean GCD Algorithm. */
#define BASIC    1
/** Lehmer's fast GCD Algorithm. */
#define LEHME    2
/** Stein's binary GCD Algorithm. */
#define STEIN    3
/** Chosen multiple precision greatest common divisor method. */
#define BN_GCD   BASIC

/** Basic prime generation. */
#define BASIC    1
/** Safe prime generation. */
#define SAFEP    2
/** Strong prime generation. */
#define STRON    3
/** Chosen prime generation algorithm. */
#define BN_GEN   BASIC

/** Multiple precision arithmetic method */
#define BN_METHD "COMBA;COMBA;MONTY;SLIDE;BASIC;BASIC"

/** Prime field size in bits. */
#define FP_PRIME 381
/** Number of Karatsuba steps. */
#define FP_KARAT 0
/** Prefer Pseudo-Mersenne primes over random primes. */
/* #undef FP_PMERS */
/** Use -1 as quadratic non-residue. */
/* #undef FP_QNRES */
/** Width of window processing for exponentiation methods. */
#define FP_WIDTH 4

/** Schoolbook addition. */
#define BASIC    1
/** Integrated modular addtion. */
#define INTEG    3
/** Chosen prime field multiplication method. */
#define FP_ADD   INTEG

/** Schoolbook multiplication. */
#define BASIC    1
/** Comba multiplication. */
#define COMBA    2
/** Integrated modular multiplication. */
#define INTEG    3
/** Chosen prime field multiplication method. */
#define FP_MUL   INTEG

/** Schoolbook squaring. */
#define BASIC    1
/** Comba squaring. */
#define COMBA    2
/** Integrated modular squaring. */
#define INTEG    3
/** Reuse multiplication for squaring. */
#define MULTP    4
/** Chosen prime field multiplication method. */
#define FP_SQR   INTEG

/** Division-based reduction. */
#define BASIC    1
/** Fast reduction modulo special form prime. */
#define QUICK    2
/** Montgomery modular reduction. */
#define MONTY    3
/** Chosen prime field reduction method. */
#define FP_RDC   MONTY

/** Inversion by Fermat's Little Theorem. */
#define BASIC    1
/** Binary inversion. */
#define BINAR    2
/** Integrated modular multiplication. */
#define MONTY    3
/** Extended Euclidean algorithm. */
#define EXGCD    4
/** Use implementation provided by the lower layer. */
#define LOWER    7
/** Chosen prime field inversion method. */
#define FP_INV   LOWER

/** Binary modular exponentiation. */
#define BASIC    1
/** Sliding window modular exponentiation. */
#define SLIDE    2
/** Constant-time Montgomery powering ladder. */
#define MONTY    3
/** Chosen multiple precision modular exponentiation method. */
#define FP_EXP   SLIDE

/** Prime field arithmetic method */
#define FP_METHD "INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE"

/** Basic quadratic extension field arithmetic. */
#define BASIC    1
/** Integrated extension field arithmetic. */
#define INTEG    3
/* Chosen extension field arithmetic method. */
#define FPX_QDR   INTEG

/** Basic cubic extension field arithmetic. */
#define BASIC    1
/** Integrated extension field arithmetic. */
#define INTEG    3
/* Chosen extension field arithmetic method. */
#define FPX_CBC   INTEG

/** Basic quadratic extension field arithmetic. */
#define BASIC    1
/** Lazy-reduced extension field arithmetic. */
#define LAZYR    2
/* Chosen extension field arithmetic method. */
#define FPX_RDC   LAZYR

/** Prime extension field arithmetic method */
#define FPX_METHD "INTEG;INTEG;LAZYR"

/** Irreducible polynomial size in bits. */
#define FB_POLYN 283
/** Number of Karatsuba steps. */
#define FB_KARAT 0
/** Prefer trinomials over pentanomials. */
#define FB_TRINO
/** Prefer square-root friendly polynomials. */
/* #undef FB_SQRTF */
/** Precompute multiplication table for sqrt(z). */
#define FB_PRECO
/** Width of window processing for exponentiation methods. */
#define FB_WIDTH 4

/** Shift-and-add multiplication. */
#define BASIC    1
/** Lopez-Dahab multiplication. */
#define LODAH	 2
/** Integrated modular multiplication. */
#define INTEG	 3
/** Left-to-right Comb multiplication. */
#define LCOMB	 4
/** Right-to-left Comb multiplication. */
#define RCOMB	 5
/** Chosen binary field multiplication method. */
#define FB_MUL   LODAH

/** Basic squaring. */
#define BASIC    1
/** Table-based squaring. */
#define RELIC_TABLE    2
/** Integrated modular squaring. */
#define INTEG	 3
/** Chosen binary field squaring method. */
#define FB_SQR   LUTBL

/** Shift-and-add modular reduction. */
#define BASIC    1
/** Fast reduction modulo a trinomial or pentanomial. */
#define QUICK	 2
/** Chosen binary field modular reduction method. */
#define FB_RDC   QUICK

/** Square root by repeated squaring. */
#define BASIC    1
/** Fast square root extraction. */
#define QUICK	 2
/** Chosen binary field modular reduction method. */
#define FB_SRT   QUICK

/** Trace by repeated squaring. */
#define BASIC    1
/** Fast trace computation. */
#define QUICK	 2
/** Chosen trace computation method. */
#define FB_TRC   QUICK

/** Solve by half-trace computation. */
#define BASIC    1
/** Solve with precomputed half-traces. */
#define QUICK	 2
/** Chosen method to solve a quadratic equation. */
#define FB_SLV   QUICK

/** Inversion by Fermat's Little Theorem. */
#define BASIC    1
/** Binary inversion. */
#define BINAR    2
/** Almost inverse algorithm. */
#define ALMOS    3
/** Extended Euclidean algorithm. */
#define EXGCD    4
/** Itoh-Tsuji inversion. */
#define ITOHT    5
/** Hardware-friendly inversion by Brunner-Curiger-Hofstetter.*/
#define BRUCH    6
/** Use implementation provided by the lower layer. */
#define LOWER    7
/** Chosen binary field inversion method. */
#define FB_INV   EXGCD

/** Binary modular exponentiation. */
#define BASIC    1
/** Sliding window modular exponentiation. */
#define SLIDE    2
/** Constant-time Montgomery powering ladder. */
#define MONTY    3
/** Chosen multiple precision modular exponentiation method. */
#define FB_EXP   SLIDE

/** Iterated squaring/square-root by consecutive squaring/square-root. */
#define BASIC    1
/** Iterated squaring/square-root by table-based method. */
#define QUICK	 2
/** Chosen method to solve a quadratic equation. */
#define FB_ITR   QUICK

/** Binary field arithmetic method */
#define FB_METHD "LODAH;LUTBL;QUICK;QUICK;QUICK;QUICK;EXGCD;SLIDE;QUICK"

/** Support for ordinary curves. */
/* #undef EP_PLAIN */
/** Support for supersingular curves. */
/* #undef EP_SUPER */
/** Support for prime curves with efficient endormorphisms. */
#define EP_ENDOM
/** Use mixed coordinates. */
#define EP_MIXED
/** Build precomputation table for generator. */
#define EP_PRECO
/** Width of precomputation table for fixed point methods. */
#define EP_DEPTH 4
/** Width of window processing for unknown point methods. */
#define EP_WIDTH 4

/** Affine coordinates. */
#define BASIC	 1
/** Projective coordinates. */
#define PROJC	 2
/** Chosen prime elliptic curve coordinate method. */
#define EP_ADD	 PROJC

/** Binary point multiplication. */
#define BASIC	 1
/** Sliding window. */
#define SLIDE    2
/** Montgomery powering ladder. */
#define MONTY	 3
/** Left-to-right Width-w NAF. */
#define LWNAF	 4
/** Chosen prime elliptic curve point multiplication method. */
#define EP_MUL	 LWNAF

/** Binary point multiplication. */
#define BASIC	 1
/** Yao's windowing method. */
#define YAOWI	 2
/** NAF windowing method. */
#define NAFWI	 3
/** Left-to-right Width-w NAF. */
#define LWNAF	 4
/** Single-table comb method. */
#define COMBS	 5
/** Double-table comb method. */
#define COMBD    6
/** Chosen prime elliptic curve point multiplication method. */
#define EP_FIX	 COMBS

/** Basic simultaneouns point multiplication. */
#define BASIC    1
/** Shamir's trick. */
#define TRICK    2
/** Interleaving of w-(T)NAFs. */
#define INTER    3
/** Joint sparse form. */
#define JOINT    4
/** Chosen prime elliptic curve simulteanous point multiplication method. */
#define EP_SIM   INTER

/** Prime elliptic curve arithmetic method. */
#define EP_METHD "PROJC;LWNAF;COMBS;INTER"

/** Support for ordinary curves without endormorphisms. */
#define EB_PLAIN
/** Support for Koblitz anomalous binary curves. */
#define EB_KBLTZ
/** Use mixed coordinates. */
#define EB_MIXED
/** Build precomputation table for generator. */
#define EB_PRECO
/** Width of precomputation table for fixed point methods. */
#define EB_DEPTH 4
/** Width of window processing for unknown point methods. */
#define EB_WIDTH 4

/** Binary elliptic curve arithmetic method. */
#define EB_METHD "PROJC;LWNAF;COMBS;INTER"

/** Affine coordinates. */
#define BASIC	 1
/** L�pez-Dahab Projective coordinates. */
#define PROJC	 2
/** Chosen binary elliptic curve coordinate method. */
#define EB_ADD	 PROJC

/** Binary point multiplication. */
#define BASIC	 1
/** L�pez-Dahab point multiplication. */
#define LODAH	 2
/** Halving. */
#define HALVE    3
/** Left-to-right width-w (T)NAF. */
#define LWNAF	 4
/** Right-to-left width-w (T)NAF. */
#define RWNAF	 5
/** Chosen binary elliptic curve point multiplication method. */
#define EB_MUL	 LWNAF

/** Binary point multiplication. */
#define BASIC	 1
/** Yao's windowing method. */
#define YAOWI	 2
/** NAF windowing method. */
#define NAFWI	 3
/** Left-to-right Width-w NAF. */
#define LWNAF	 4
/** Single-table comb method. */
#define COMBS	 5
/** Double-table comb method. */
#define COMBD    6
/** Chosen binary elliptic curve point multiplication method. */
#define EB_FIX	 COMBS

/** Basic simultaneouns point multiplication. */
#define BASIC    1
/** Shamir's trick. */
#define TRICK    2
/** Interleaving of w-(T)NAFs. */
#define INTER    3
/** Joint sparse form. */
#define JOINT    4
/** Chosen binary elliptic curve simulteanous point multiplication method. */
#define EB_SIM   INTER

/** Prefer curves with efficient endomorphisms. */
/* #undef EC_ENDOM */

/** Binary point multiplication. */
#define BASIC	 1
/** Sliding window. */
#define SLIDE    2
/** Montgomery powering ladder. */
#define MONTY	 3
/** Left-to-right Width-w NAF. */
#define LWNAF	 4
/** Left-to-right Width-w NAF with mixed coordinates. */
#define LWNAF_MIXED	 7
/** Fixed window. */
#define FIXED	 8
/** Chosen prime elliptic twisted Edwards curve point multiplication method. */
#define ED_MUL	 LWNAF

#define ED_PLAIN

/** Build precomputation table for generator. */
#define ED_PRECO
/** Width of precomputation table for fixed point methods. */
#define ED_DEPTH 4
/** Width of window processing for unknown point methods. */
#define ED_WIDTH 4

/** Simple projective twisted Edwards coordinates */
#define PROJC	 2
/** Extended projective twisted Edwards coordinates */
#define EXTND	 3
/** Chosen binary elliptic curve coordinate method. */
#define ED_ADD	 PROJC

/** Binary point multiplication. */
#define BASIC	 1
/** Yao's windowing method. */
#define YAOWI	 2
/** NAF windowing method. */
#define NAFWI	 3
/** Left-to-right Width-w NAF. */
#define LWNAF	 4
/** Single-table comb method. */
#define COMBS	 5
/** Double-table comb method. */
#define COMBD    6
/** Chosen prime elliptic twisted Edwards curve point multiplication method. */
#define ED_FIX	 COMBS

/** Chosen prime elliptic curve simulteanous point multiplication method. */
#define ED_SIM   INTER

#define ED_METHD "PROJC;LWNAF;COMBS;INTER"

/** Prime curves. */
#define PRIME    1
/** Binary curves. */
#define CHAR2    2
/** Edwards curves */
#define EDWARD   3
/** Chosen elliptic curve type. */
#define EC_CUR	 PRIME

/** Chosen elliptic curve cryptography method. */
#define EC_METHD "PRIME"

/** Parallel implementation. */
/* #undef PP_PARAL */

/** Basic quadratic extension field arithmetic. */
#define BASIC    1
/** Lazy-reduced extension field arithmetic. */
#define LAZYR    2
/* Chosen extension field arithmetic method. */
#define PP_EXT   BASIC

/** Bilinear pairing method. */
#define PP_METHD "BASIC;OATEP"

/** Tate pairing. */
#define TATEP    1
/** Weil pairing. */
#define WEILP    2
/** Optimal ate pairing. */
#define OATEP    3
/** Beta Weil pairing. */
#define BWEIL    4
/** Chosen pairing method over prime elliptic curves. */
#define PP_MAP   OATEP

/** SHA-1 hash function. */
#define SHONE          1
/** SHA-224 hash function. */
#define SH224          2
/** SHA-256 hash function. */
#define SH256          3
/** SHA-384 hash function. */
#define SH384          4
/** SHA-512 hash function. */
#define SH512          5
/** BLAKE2s-160 hash function. */
#define B2S160         6
/** BLAKE2s-256 hash function. */
#define B2S256         7
/** Chosen hash function. */
#define MD_MAP   SH256

/** Choice of hash function. */
#define MD_METHD "SH256"

/** RSA without padding. */
#define BASIC    1
/** RSA PKCS#1 v1.5 padding. */
#define PKCS1    2
/** RSA PKCS#1 v2.1 padding. */
#define PKCS2    3
/** Chosen RSA padding method. */
#define CP_RSAPD PKCS1

/** Slow RSA decryption/signature. */
#define BASIC    1
/** Fast RSA decryption/signature with CRT. */
#define QUICK    2
/** Chosen RSA method. */
#define CP_RSA   QUICK

/** Standard ECDSA. */
#define BASIC    1
/** ECDSA with fast verification. */
#define QUICK    2
/** Chosen ECDSA method. */
#define CP_ECDSA 

/** Automatic memory allocation. */
#define AUTO     1
/** Static memory allocation. */
#define	STATIC   2
/** Dynamic memory allocation. */
#define DYNAMIC  3
/** Stack memory allocation. */
#define STACK    4
/** Chosen memory allocation policy. */
#define ALLOC    AUTO

/** NIST HASH-DRBG generator. */
#define HASH     1
/** NIST HMAC-DRBG generator. */
#define RELIC_HMAC     2
/** Operating system underlying generator. */
#define UDEV     3
/** Intel RdRand instruction. */
#define RDRND    4
/** FIPS 186-2 (CN1) SHA-1 based generator. */
#define FIPS     5
/** Override library generator with the callback. */
#define CALL     6
/** Chosen random generator. */
#define RAND     HASH

/** Use Windows' CryptGenRandom. */
#define WCGR     1
/** Device node generator. */
#define DEV      2
/** Device node generator. */
#define UDEV     3
/** Intel RdRand instruction. */
#define RDRND    4
/** Standard C library generator. */
#define LIBC     5
/** Null seed. */
#define	ZERO     6
/** Chosen random generator seeder. */
#define SEED     UDEV

/** GNU/Linux operating system. */
#define LINUX    1
/** FreeBSD operating system. */
#define FREEBSD  2
/** Windows operating system. */
#define MACOSX   3
/** Windows operating system. */
#define WINDOWS  4
/** Android operating system. */
#define DROID    5
/* Arduino platform. */
#define DUINO    6
/** Detected operation system. */
#define OPSYS    MACOSX

/** OpenMP multithreading support. */
#define OPENMP   1
/** POSIX multithreading support. */
#define PTHREAD  2
/** Chosen multithreading API. */
#define MULTI    RELIC_NONE

/** Per-process high-resolution timer. */
#define HREAL    1
/** Per-process high-resolution timer. */
#define HPROC    2
/** Per-thread high-resolution timer. */
#define HTHRD    3
/** POSIX-compatible timer. */
#define POSIX    4
/** ANSI-compatible timer. */
#define ANSI     5
/** Cycle-counting timer. */
#define CYCLE    6
/** Chosen timer. */
#define TIMER    CYCLE

/** Prefix to identity this build of the library. */
/* #undef LABEL */

#ifndef ASM

#include "relic_label.h"

/**
 * Prints the project options selected at build time.
 */
void conf_print(void);

#endif /* ASM */

#endif /* !RELIC_CONF_H */
