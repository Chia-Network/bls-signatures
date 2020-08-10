from copy import deepcopy
from secrets import token_bytes
import hashlib

from fields import Fq, Fq2, Fq6, Fq12
from ec import (
    G1Generator,
    G2Generator,
    G1Infinity,
    G2Infinity,
    G1FromBytes,
    G2FromBytes,
    default_ec,
    default_ec_twist,
    sign_Fq2,
    twist,
    untwist,
    y_for_x,
)
from pairing import ate_pairing
from hash_to_field import expand_message_xmd


def test_fields():
    a = Fq(17, 30)
    b = Fq(17, -18)
    c = Fq2(17, a, b)
    d = Fq2(17, a + a, Fq(17, -5))
    e = c * d
    f = e * d
    assert f != e
    e_sq = e * e
    e_sqrt = e_sq.modsqrt()
    assert pow(e_sqrt, 2) == e_sq

    a2 = Fq(
        172487123095712930573140951348,
        3012492130751239573498573249085723940848571098237509182375,
    )
    b2 = Fq(172487123095712930573140951348, 3432984572394572309458723045723849)
    c2 = Fq2(172487123095712930573140951348, a2, b2)
    assert b2 != c2

    g = Fq6(17, c, d, d * d * c)
    h = Fq6(17, a + a * c, c * b * a, b * b * d * Fq(17, 21))
    i = Fq12(17, g, h)
    assert ~(~i) == i
    assert (~(i.root)) * i.root == Fq6.one(17)
    x = Fq12(17, Fq6.zero(17), i.root)
    assert (~x) * x == Fq12.one(17)

    j = Fq6(17, a + a * c, Fq2.zero(17), Fq2.zero(17))
    j2 = Fq6(17, a + a * c, Fq2.zero(17), Fq2.one(17))
    assert j == (a + a * c)
    assert j2 != (a + a * c)
    assert j != j2

    # Test frob_coeffs
    one = Fq(default_ec.q, 1)
    two = one + one
    a = Fq2(default_ec.q, two, two)
    b = Fq6(default_ec.q, a, a, a)
    c = Fq12(default_ec.q, b, b)
    for base in (a, b, c):
        for expo in range(1, base.extension):
            assert base.qi_power(expo) == pow(base, pow(default_ec.q, expo))


def test_ec():
    q = default_ec.q
    g = G1Generator()

    assert g.is_on_curve()
    assert 2 * g == g + g
    assert (3 * g).is_on_curve()
    assert 3 * g == g + g + g

    g2 = G2Generator()
    assert g2.x * (Fq(q, 2) * g2.y) == Fq(q, 2) * (g2.x * g2.y)
    assert g2.is_on_curve()
    s = g2 + g2
    assert untwist(twist(s.to_affine())) == s.to_affine()
    assert untwist(5 * twist(s.to_affine())) == (5 * s).to_affine()
    assert 5 * twist(s.to_affine()) == twist((5 * s).to_affine())
    assert s.is_on_curve()
    assert g2.is_on_curve()
    assert g2 + g2 == 2 * g2
    assert g2 * 5 == (g2 * 2) + (2 * g2) + g2
    y = y_for_x(g2.x, default_ec_twist, Fq2)
    assert y == g2.y or -y == g2.y

    g_j = G1Generator()
    g2_j = G2Generator()
    g2_j2 = G2Generator() * 2
    assert g.to_affine().to_jacobian() == g
    assert (g_j * 2).to_affine() == g.to_affine() * 2
    assert (g2_j + g2_j2).to_affine() == g2.to_affine() * 3


def test_edge_case_sign_Fq2():
    q = default_ec.q
    a = Fq(q, 62323)
    test_case_1 = Fq2(q, a, Fq(q, 0))
    test_case_2 = Fq2(q, -a, Fq(q, 0))
    assert sign_Fq2(test_case_1) != sign_Fq2(test_case_2)

    test_case_3 = Fq2(q, Fq(q, 0), a)
    test_case_4 = Fq2(q, Fq(q, 0), -a)

    assert sign_Fq2(test_case_3) != sign_Fq2(test_case_4)


def test_xmd():
    msg = token_bytes(48)
    dst = token_bytes(16)
    ress = {}
    for length in range(16, 8192):
        result = expand_message_xmd(msg, dst, length, hashlib.sha512)
        assert length == len(result)
        key = result[:16]
        ress[key] = ress.get(key, 0) + 1
    assert all(x == 1 for x in ress.values())


def test_elements():
    i1 = int.from_bytes(bytes([1, 2]), byteorder="big")
    i2 = int.from_bytes(bytes([3, 1, 4, 1, 5, 9]), byteorder="big")
    b1 = i1
    b2 = i2
    g1 = G1Generator()
    g2 = G2Generator()
    u1 = G1Infinity()
    u2 = G2Infinity()

    x1 = g1 * b1
    x2 = g1 * b2
    y1 = g2 * b1
    y2 = g2 * b2

    # Implicit conversion from python ints to BNWrapperWrapperWrapper
    assert x1 == g1 * i1 == i1 * g1
    assert x2 == g1 * i2 == i2 * g1
    assert y1 == g2 * i1 == i1 * g2
    assert y2 == g2 * i2 == i2 * g2

    # G1
    assert x1 != x2
    assert x1 * b1 == b1 * x1
    assert x1 * b1 != x1 * b2

    left = x1 + u1
    right = x1

    assert left == right
    assert x1 + x2 == x2 + x1
    assert x1 + x1.negate() == u1
    assert x1 == G1FromBytes(bytes(x1))
    copy = deepcopy(x1)
    assert x1 == copy
    x1 += x2
    assert x1 != copy

    # G2
    assert y1 != y2
    assert y1 * b1 == b1 * y1
    assert y1 * b1 != y1 * b2
    assert y1 + u2 == y1
    assert y1 + y2 == y2 + y1
    assert y1 + y1.negate() == u2
    assert y1 == G2FromBytes(bytes(y1))
    copy = deepcopy(y1)
    assert y1 == copy
    y1 += y2
    assert y1 != copy

    # pairing operation
    pair = ate_pairing(x1, y1)
    assert pair != ate_pairing(x1, y2)
    assert pair != ate_pairing(x2, y1)
    copy = deepcopy(pair)
    assert pair == copy
    pair = None
    assert pair != copy

    sk = 728934712938472938472398074
    pk = sk * g1
    Hm = y2 * 12371928312 + y2 * 12903812903891023

    sig = Hm * sk

    assert ate_pairing(g1, sig) == ate_pairing(pk, Hm)


test_fields()
test_ec()
test_xmd()
test_edge_case_sign_Fq2()
test_elements()
