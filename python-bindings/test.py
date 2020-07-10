# flake8: noqa: E501
from blspy import (
    BNWrapper as BN,
    G1Element as G1,
    G2Element as G2,
    GTElement as GT,
    BasicScheme,
    AugScheme,
    PopScheme,
)


def test():
    b1 = BN([1, 2])
    b2 = BN([3, 1, 4, 1, 5, 9])
    i1 = int.from_bytes(bytes([1, 2]), byteorder="big", signed=False)
    i2 = int.from_bytes(bytes([3, 1, 4, 1, 5, 9]), byteorder="big", signed=False)
    g1 = G1.generator()
    g2 = G2.generator()
    u1 = G1()  # unity
    u2 = G2()

    x1 = g1 * b1
    x2 = g1 * b2
    y1 = g2 * b1
    y2 = g2 * b2

    # Implicit conversion from python ints to BNWrapper
    assert x1 == g1 * i1 == i1 * g1
    assert x2 == g1 * i2 == i2 * g1
    assert y1 == g2 * i1 == i1 * g2
    assert y2 == g2 * i2 == i2 * g2

    # G1
    assert x1 != x2
    assert x1 * b1 == b1 * x1
    assert x1 * b1 != x1 * b2
    assert x1 + u1 == x1
    assert x1 + x2 == x2 + x1
    assert x1 + x1.inverse() == u1

    # G2
    assert y1 != y2
    assert y1 * b1 == b1 * y1
    assert y1 * b1 != y1 * b2
    assert y1 + u2 == y1
    assert y1 + y2 == y2 + y1
    assert y1 + y1.inverse() == u2

    # pairing operation
    pair = x1 & y1
    assert pair != x1 & y2
    assert pair != x2 & y1
    assert pair == x1.pair(y1)

    # Make G1/G2element from bytes object, list[int]
    assert g1 == G1(
        bytes.fromhex(
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        )
    )
    #assert g2 == G2(
    #    bytes.fromhex(
    #        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
    #    )
    #)
    assert g1 == G1(
        [
            151,
            241,
            211,
            167,
            49,
            151,
            215,
            148,
            38,
            149,
            99,
            140,
            79,
            169,
            172,
            15,
            195,
            104,
            140,
            79,
            151,
            116,
            185,
            5,
            161,
            78,
            58,
            63,
            23,
            27,
            172,
            88,
            108,
            85,
            232,
            63,
            249,
            122,
            26,
            239,
            251,
            58,
            240,
            10,
            219,
            34,
            198,
            187,
        ]
    )
    assert u1 == G1([192] + [0] * 47)
    #assert u2 == G2([192] + [0] * 47 + [192] + [0] * 47)


test()
print("All tests done.")

"""
Copyright 2018 Chia Network Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
