from ec import (
    G1Generator,
    G2Generator,
    G1Infinity,
    G2Infinity,
    G1FromBytes,
    G2FromBytes,
)
from copy import deepcopy
from pairing import ate_pairing


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


test_elements()
