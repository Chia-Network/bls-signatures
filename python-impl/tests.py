# flake8: noqa: E501

from ec import (generator_Fq, generator_Fq2, default_ec, default_ec_twist,
                y_for_x, hash_to_point_Fq, hash_to_point_Fq2,
                twist, untwist, rand_scalar)
from fields import Fq2, Fq6, Fq12, Fq
from bls import BLSPrivateKey, BLS, AggregationInfo
import time

def test_fields():
    a = Fq(17, 30)
    b = Fq(17, -18)
    c = Fq2(17, a, b)
    d = Fq2(17, a + a, -5)
    e = c * d
    f = e * d
    assert(f != e)
    e_sq = e*e
    e_sqrt = e_sq.modsqrt()
    assert(pow(e_sqrt, 2) == e_sq)

    a2 = Fq(172487123095712930573140951348,
            3012492130751239573498573249085723940848571098237509182375)
    b2 = Fq(172487123095712930573140951348, 3432984572394572309458723045723849)
    c2 = Fq2(172487123095712930573140951348, a2, b2)
    assert(b2 != c2)

    g = Fq6(17, c, d, d*d*c)
    h = Fq6(17, a + a*c, c*b*a, b*b*d*21)
    i = Fq12(17, g, h)
    assert(~(~i) == i)
    assert((~(i.root)) * i.root == Fq6.one(17))
    x = Fq12(17, Fq6.zero(17), i.root)
    assert((~x) * x == Fq12.one(17))

    j = Fq6(17, a + a*c, Fq2.zero(17), Fq2.zero(17))
    j2 = Fq6(17, a + a*c, Fq2.zero(17), Fq2.one(17))
    assert(j == (a + a*c))
    assert(j2 != (a + a*c))
    assert(j != j2)


def test_ec():
    g = generator_Fq(default_ec)

    assert(g.is_on_curve())
    assert(2*g == g + g)
    assert((3*g).is_on_curve())
    assert(3*g == g + g + g)
    P = hash_to_point_Fq("")
    assert(P.is_on_curve())

    g2 = generator_Fq2(default_ec_twist)
    assert(g2.x * (2 * g2.y) == 2*(g2.x * g2.y))
    assert(g2.is_on_curve())
    s = g2 + g2
    assert(untwist(twist(s)) == s)
    assert(untwist(5 * twist(s)) == 5 * s)
    assert(5 * twist(s) == twist(5 * s))
    assert(s.is_on_curve())
    assert(g2.is_on_curve())
    assert(g2 + g2 == 2 * g2)
    assert(g2 * 5 == (g2 * 2) + (2 * g2) + g2)
    y = y_for_x(g2.x, default_ec_twist, Fq2)
    assert(y[0] == g2.y or y[1] == g2.y)
    assert(hash_to_point_Fq2("chia") == hash_to_point_Fq2("chia"))

    g_j = generator_Fq(default_ec_twist).to_jacobian()
    g2_j = generator_Fq2(default_ec_twist).to_jacobian()
    g2_j2 = (generator_Fq2(default_ec_twist) * 2).to_jacobian()
    assert(g.to_jacobian().to_affine() == g)
    assert((g_j * 2).to_affine() == g * 2)
    assert((g2_j + g2_j2).to_affine() == g2 * 3)


def test_vectors():
    sk1 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    pk1 = sk1.get_public_key()
    sig1 = sk1.sign(bytes([7, 8, 9]))

    sk2 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))
    pk2 = sk2.get_public_key()
    sig2 = sk2.sign(bytes([7, 8, 9]))
    assert(sk1.serialize() == bytes.fromhex("022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e"))
    assert(pk1.get_fingerprint() == 0x26d53247)
    assert(pk2.get_fingerprint() == 0x289bb56e)
    assert(sig1.serialize() == bytes.fromhex("0f562d96ddabc780ce2ec4b00078e13ee265d7fb24fc2358f3aeb900d7e05f0c880388fe0abc4b460ab1ea3f843c0c28042503e005f357d3124151b87ba2df18b6a5d91afb9cd09cfed16876a25e505fe3bdfb8ccf1ba18be4ca35a095d81957"))
    assert(sig2.serialize() == bytes.fromhex("8388b5451e0d387fbcade62af7563705635f7eedaaf5c2d97ce2e116150f159256b7fe045f03a8a0013312bd5ea153130943caa0f409b6fac4850b0102e5f5f8ffc27ba900bd624317ba19cb19c5a681a083ef8167a4930bbc17aac8ea40bbd5"))

    agg_sig = BLS.aggregate_sigs([sig1, sig2])
    agg_pk = BLS.aggregate_public_keys([pk1, pk2], True)
    agg_sk = BLS.aggregate_private_keys([sk1, sk2], [pk1, pk2], True)
    assert(agg_sig.serialize() == bytes.fromhex("067d44075175669de7ebd5151c256d60b6a7ebbe06d0f680d135f26f912b7fbbe049a1b42fa910bbfa8a38e4466c4dbf02062fd347174015624b1885351104830354a89d307bc509489cd33fa0c79826672288250f27024b8ea0bcafcdcfd386"))
    assert(agg_sk.sign(bytes([7, 8, 9])).serialize() == agg_sig.serialize())


    assert(BLS.verify(sig1))
    assert(BLS.verify(agg_sig))

    agg_sig.set_aggregation_info(AggregationInfo.from_msg(agg_pk, bytes([7, 8, 9])))
    assert(BLS.verify(agg_sig))

    sig1.set_aggregation_info(sig2.aggregation_info)
    assert(not BLS.verify(sig1))

    sig3 = sk1.sign(bytes([1, 2, 3]))
    sig4 = sk1.sign(bytes([1, 2, 3, 4]))
    sig5 = sk2.sign(bytes([1, 2]))

    agg_sig2 = BLS.aggregate_sigs([sig3, sig4, sig5])
    assert(agg_sig2.serialize() == bytes.fromhex("0ed044dbb085e89fbd2b5823ae8406becc4d0e18a96fa9a4d116bb01ea93ac65f7a0331cfc0330961c03d0f9283e66fe101058df847878374716231e4d243bbf89ee82acc7d7bdcc091e20b097ac58823679b63bd0215556263645bcc846a0a0"));
    assert(BLS.verify(agg_sig2))


def test_vectors2():
    m1 = bytes([1, 2, 3, 40])
    m2 = bytes([5, 6, 70, 201])
    m3 = bytes([9, 10, 11, 12, 13])
    m4 = bytes([15, 63, 244, 92, 0, 1])

    sk1 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    pk1 = sk1.get_public_key()

    sk2 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))
    pk2 = sk2.get_public_key()

    sig1 = sk1.sign(m1)
    sig2 = sk2.sign(m2)
    sig3 = sk2.sign(m1)
    sig4 = sk1.sign(m3)
    sig5 = sk1.sign(m1)
    sig6 = sk1.sign(m4)

    sig_L = BLS.aggregate_sigs([sig1, sig2])
    sig_R = BLS.aggregate_sigs([sig3, sig4, sig5])
    assert(BLS.verify(sig_L))
    assert(BLS.verify(sig_R))

    sig_final = BLS.aggregate_sigs([sig_L, sig_R, sig6])
    assert(sig_final.serialize() == bytes.fromhex("97f79f27fbd08b77666ca0f7be9c513df86e0ef41e8569a9a8dac7f368d61ec723242b4cce2576875437eb648dd9baef0906ec6424b1e5ecabec21a488b24ddf19a118b7b11848489c57a148145a383f776727e04858ee67aefaef99af31b8d9"))
    assert(BLS.verify(sig_final))


def test_bls():
    sk = BLSPrivateKey(rand_scalar())
    sk2 = BLSPrivateKey(rand_scalar())
    sig = sk.sign("hello world2")
    pk = sk.get_public_key()
    pk2 = sk2.get_public_key()
    sig2 = sk2.sign("hello world2")
    print(sk)
    print(pk, pk2)
    print(sig)
    print(BLS.aggregate_sigs_simple([sig, sig2]))


test_fields()
test_ec()
test_bls()
test_vectors()
test_vectors2()


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
