# flake8: noqa: E501

import time
from ec import (generator_Fq, generator_Fq2, default_ec, default_ec_twist,
                y_for_x, hash_to_point_Fq, hash_to_point_Fq2,
                twist, untwist, sw_encode)
import random
from fields import Fq2, Fq6, Fq12, Fq
from bls import BLS
from keys import BLSPrivateKey, BLSPublicKey, ExtendedPrivateKey
from aggregation_info import AggregationInfo
from signature import BLSSignature
from util import hash256


def rand_scalar(ec=default_ec):
    return random.randrange(1, ec.n)


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

    assert(sw_encode(Fq(default_ec.q, 0)).infinity)
    assert(sw_encode(Fq(default_ec.q, 1)) == sw_encode(Fq(default_ec.q, -1)).negate())
    assert(sw_encode(Fq(default_ec.q, 0x019cfaba0c258165d092f6bca9a081871e62a126c499340dc71c0e9527f923f3b299592a7a9503066cc5362484d96dd7)) == generator_Fq())
    assert(sw_encode(Fq(default_ec.q, 0x186417302d5a65347a88b0f999ab2b504614aa5e2eebdeb1a014c40bceb7d2306c12a6d436befcf94d39c9db7b263cd4)) == generator_Fq().negate())


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
    assert(sig1.serialize() == bytes.fromhex("020fcab96d75902487099488e4c8f59134ef7264c4c7bc0ef9aebad608f235090c5d97cc483eb6847808d13beb4422f70ad97470d4d1f0a3f51cb370c80956878da8541ab6bcb290a479053dae06037d57e89b445b37eb38c20232e68d08d1de"))
    assert(sig2.serialize() == bytes.fromhex("040e2e15bd13be3e39e20569170531e581b4fece0941212e38599afe8cf7334ac945a85f7a2d4c18963def6b3cc7a0db191b90334a8036d2658da9dbafbdd8eb4ba3527197ffc42504949a6b0532bce3402b7f99191f892e0304594841e4d617"))

    agg_sig = BLS.aggregate_sigs([sig1, sig2])
    agg_pk = BLS.aggregate_pub_keys([pk1, pk2], True)
    agg_sk = BLS.aggregate_priv_keys([sk1, sk2], [pk1, pk2], True)
    assert(agg_sig.serialize() == bytes.fromhex("85b8fc474f39b31c23d16d4cce66f80345af36a791309a1820998ae2364eed03b2277221570c5e1545082dd1ec39fe871399a835a253e3b79d776195b481c1555ad2eb3fbb1a8733c7b7897b5302fa03f6d6ca9c8151432c73e2afc76dccb471"))
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
    assert(BLS.verify(agg_sig2))
    assert(agg_sig2.serialize() == bytes.fromhex("90ab621b7aba2daccc07994d10687ea9b06ce89da981d269febff58466a87677cf05c35a8a662642db0bfad61cbd35b7117fa2a4e10b94dcf49e991a453ae5b12b55dee93fcdb5411bca41375370808892d91d54afe32556aa77db47b01a2375"));


def test_vectors2():
    m1 = bytes([1, 2, 3, 40])
    m2 = bytes([5, 6, 70, 201])
    m3 = bytes([9, 10, 11, 12, 13])
    m4 = bytes([15, 63, 244, 92, 0, 1])

    sk1 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    sk2 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))

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
    assert(sig_final.serialize() == bytes.fromhex("948affeee161fab3d8569d86b97ad9d899dd000c7feb1c3e750a429c3f66eeb7a883296399304840f2816cceaf94103712925cfe0f6e75c03ce2d68213c9368a72b19d09923dcfd9b5589fb1c72ceeb3d59b7028b8d0c19b3305dde5e9fdff8e"))
    assert(BLS.verify(sig_final))
    quotient = sig_final.divide_by([sig2, sig5, sig6])
    assert(BLS.verify(quotient))
    assert(BLS.verify(sig_final))
    assert(quotient.serialize() == bytes.fromhex("81044ddc441b1e8a4f33bcfbe69f72197533dc735be0c754aea132624b69c2fe29a7d58dd05d0784308dc9237bf4043400b2b38dbd18fce224f042558a01777c41bcf64415d497e3fe98440c8a23e9fa52f5b9dda57e02d5321eb7bfce35e817"))
    assert(quotient.divide_by([]) == quotient)
    try:
        quotient.divide_by([sig6])
        assert(False)  # Should fail due to not subset
    except:
        pass
    sig_final.divide_by([sig1]) # Should not throw
    try:
        sig_final.divide_by([sig_L]) # Should throw due to not unique
        assert(False)  # Should fail due to not unique
    except:
        pass

    # Divide by aggregate
    sig7 = sk2.sign(m3)
    sig8 = sk2.sign(m4)
    sig_R2 = BLS.aggregate_sigs([sig7, sig8])
    sig_final2 = BLS.aggregate_sigs([sig_final, sig_R2])
    quotient2 = sig_final2.divide_by([sig_R2])
    assert(BLS.verify(quotient2))
    assert(quotient2.serialize() == bytes.fromhex("06de76d808f06cb3227dab2711087e4bf8b1e7376a88a426413503afd77f3e3498cce91464762b0c8f604379b2175ed0039b885ccd5f2756b3ba0d3296b9ff0fa6c5af4fa5eb77e61d292c17ce07333826cb39abd599f3635c6e418fdf88fcd4"))


def test_vectors3():
    seed = bytes([1, 50, 6, 244, 24, 199, 1, 25])
    esk =  ExtendedPrivateKey.from_seed(seed)
    assert(esk.private_key.get_public_key().get_fingerprint() == 0xa4700b27)
    assert(esk.chain_code.hex() == "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3")
    esk77 = esk.private_child(77 + 2**31)
    assert(esk77.chain_code.hex() == "f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b")
    assert(esk77.private_key.get_public_key().get_fingerprint() == 0xa8063dcf)

    assert(esk.private_child(3)
              .private_child(17)
              .private_key
              .get_public_key()
              .get_fingerprint() == 0xff26a31f)

    assert(esk.get_extended_public_key()
              .public_child(3)
              .public_child(17)
              .get_public_key()
              .get_fingerprint() == 0xff26a31f)


def test1():
    seed = bytes([0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22])
    sk = BLSPrivateKey.from_seed(seed)
    pk = sk.get_public_key()

    msg = bytes([100, 2, 254, 88, 90, 45, 23])

    sig = sk.sign(msg)

    sk_bytes = sk.serialize()
    pk_bytes = pk.serialize()
    sig_bytes = sig.serialize()

    sk = BLSPrivateKey.from_bytes(sk_bytes)
    pk = BLSPublicKey.from_bytes(pk_bytes)
    sig = BLSSignature.from_bytes(sig_bytes)

    sig.set_aggregation_info(AggregationInfo.from_msg(pk, msg))
    assert(BLS.verify(sig))

    seed = bytes([1]) + seed[1:]
    sk1 = BLSPrivateKey.from_seed(seed)
    seed = bytes([2]) + seed[1:]
    sk2 = BLSPrivateKey.from_seed(seed)

    pk1 = sk1.get_public_key()
    sig1 = sk1.sign(msg)

    pk2 = sk2.get_public_key()
    sig2 = sk2.sign(msg)

    agg_sig = BLS.aggregate_sigs([sig1, sig2])
    agg_pubkey = BLS.aggregate_pub_keys([pk1, pk2], True)

    agg_sig.set_aggregation_info(AggregationInfo.from_msg(agg_pubkey, msg))
    assert(BLS.verify(agg_sig))

    seed = bytes([3]) + seed[1:]
    sk3 = BLSPrivateKey.from_seed(seed)
    pk3 = sk3.get_public_key()
    msg2 = bytes([100, 2, 254, 88, 90, 45, 23])

    sig1 = sk1.sign(msg)
    sig2 = sk2.sign(msg)
    sig3 = sk3.sign(msg2)
    agg_sig_l = BLS.aggregate_sigs([sig1, sig2])
    agg_sig_final = BLS.aggregate_sigs([agg_sig_l, sig3])

    sig_bytes = agg_sig_final.serialize()

    agg_sig_final = BLSSignature.from_bytes(sig_bytes)
    a1 = AggregationInfo.from_msg(pk1, msg)
    a2 = AggregationInfo.from_msg(pk2, msg)
    a3 = AggregationInfo.from_msg(pk3, msg2)
    a1a2 = AggregationInfo.merge_infos([a1, a2])
    a_final = AggregationInfo.merge_infos([a1a2, a3])
    print(a_final)
    agg_sig_final.set_aggregation_info(a_final)
    ok = BLS.verify(agg_sig_final)

    ok = BLS.verify(agg_sig_l)
    agg_sig_final = agg_sig_final.divide_by([agg_sig_l])

    ok = BLS.verify(agg_sig_final)

    agg_sk = BLS.aggregate_priv_keys([sk1, sk2], [pk1, pk2], True)
    agg_sk.sign(msg)

    seed = bytes([1, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22])

    esk = ExtendedPrivateKey.from_seed(seed)
    epk = esk.get_extended_public_key()

    sk_child = esk.private_child(0).private_child(5)
    pk_child = epk.public_child(0).public_child(5)

    buffer1 = pk_child.serialize()
    buffer2 = sk_child.serialize()

    assert(sk_child.get_extended_public_key() == pk_child)


def test2():
    seed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    seed2 = bytes([1, 20, 102, 229, 1, 157])

    sk = BLSPrivateKey.from_seed(seed)
    sk_cp = BLSPrivateKey.from_seed(seed)
    sk2 = BLSPrivateKey.from_seed(seed2)
    pk = sk.get_public_key()
    pk2 = sk2.get_public_key()
    assert(sk == sk_cp)
    assert(sk != sk2)
    assert(pk.get_fingerprint() == 0xddad59bb)

    pk2_ser = pk2.serialize()
    pk2_copy = BLSPublicKey.from_bytes(pk2_ser)
    assert(pk2 == pk2_copy)
    assert(pk != pk2)
    assert(pk2.size() == 48)
    assert(sk2.size() == 32)

    message = bytes("this is the message", "utf-8")
    sig = sk.sign(message)
    sig_ser = sig.serialize()
    sig_cp = BLSSignature.from_bytes(sig_ser)
    a1 = AggregationInfo.from_msg(pk, message)
    sig_cp.set_aggregation_info(a1)
    a2 = sig_cp.get_aggregation_info()
    assert(a1 == a2)
    sig2 = sk2.sign(message)

    assert(sig.size() == 96)
    assert(sig != sig2)
    assert(sig == sig_cp)

    sig_agg = BLS.aggregate_sigs([sig, sig2])

    result = BLS.verify(sig_cp)
    result2 = BLS.verify(sig2)
    result3 = BLS.verify(sig_agg)
    assert(result)
    assert(result2)
    assert(result3)

    sk2 = sk


test_fields()
test_ec()
test_vectors()
test_vectors2()
test_vectors3()
test1()
test2()

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
