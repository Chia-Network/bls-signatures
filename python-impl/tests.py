# flake8: noqa: E501
from aggregation_info import AggregationInfo
from ec import (default_ec, default_ec_twist, generator_Fq, generator_Fq2,
                hash_to_point_Fq, hash_to_point_Fq2, sw_encode, twist, untwist,
                y_for_x)
from fields import Fq, Fq2, Fq6, Fq12
from itertools import combinations
from keys import PrivateKey, PublicKey, ExtendedPrivateKey
import random
from signature import Signature, PrependSignature
from sys import setrecursionlimit
import time
from threshold import Threshold
from util import hash256

setrecursionlimit(10**6)


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
    g = generator_Fq(default_ec)

    assert(g.is_on_curve())
    assert(2*g == g + g)
    assert((3*g).is_on_curve())
    assert(3*g == g + g + g)
    P = hash_to_point_Fq(bytes([]))
    assert(P.is_on_curve())
    assert(P.serialize() == bytes.fromhex("12fc5ad5a2fbe9d4b6eb0bc16d530e5f263b6d59cbaf26c3f2831962924aa588ab84d46cc80d3a433ce064adb307f256"))

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
    sk1 = PrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    pk1 = sk1.get_public_key()
    sig1 = sk1.sign(bytes([7, 8, 9]))

    sk2 = PrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))
    pk2 = sk2.get_public_key()
    sig2 = sk2.sign(bytes([7, 8, 9]))
    assert(sk1.serialize() == bytes.fromhex("022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e"))
    assert(pk1.get_fingerprint() == 0x26d53247)
    assert(pk2.get_fingerprint() == 0x289bb56e)
    assert(sig1.serialize() == bytes.fromhex("93eb2e1cb5efcfb31f2c08b235e8203a67265bc6a13d9f0ab77727293b74a357ff0459ac210dc851fcb8a60cb7d393a419915cfcf83908ddbeac32039aaa3e8fea82efcb3ba4f740f20c76df5e97109b57370ae32d9b70d256a98942e5806065"))
    assert(sig2.serialize() == bytes.fromhex("975b5daa64b915be19b5ac6d47bc1c2fc832d2fb8ca3e95c4805d8216f95cf2bdbb36cc23645f52040e381550727db420b523b57d494959e0e8c0c6060c46cf173872897f14d43b2ac2aec52fc7b46c02c5699ff7a10beba24d3ced4e89c821e"))

    agg_sig = Signature.aggregate([sig1, sig2])
    agg_pk = PublicKey.aggregate([pk1, pk2], True)
    agg_sk = PrivateKey.aggregate([sk1, sk2], [pk1, pk2], True)
    assert(agg_sig.serialize() == bytes.fromhex("0a638495c1403b25be391ed44c0ab013390026b5892c796a85ede46310ff7d0e0671f86ebe0e8f56bee80f28eb6d999c0a418c5fc52debac8fc338784cd32b76338d629dc2b4045a5833a357809795ef55ee3e9bee532edfc1d9c443bf5bc658"))
    assert(agg_sk.sign(bytes([7, 8, 9])).serialize() == agg_sig.serialize())


    assert(sig1.verify())
    assert(agg_sig.verify())

    agg_sig.set_aggregation_info(AggregationInfo.from_msg(agg_pk, bytes([7, 8, 9])))
    assert(agg_sig.verify())

    sig1.set_aggregation_info(sig2.aggregation_info)
    assert(not sig1.verify())

    sig3 = sk1.sign(bytes([1, 2, 3]))
    sig4 = sk1.sign(bytes([1, 2, 3, 4]))
    sig5 = sk2.sign(bytes([1, 2]))


    agg_sig2 = Signature.aggregate([sig3, sig4, sig5])
    assert(agg_sig2.verify())
    assert(agg_sig2.serialize() == bytes.fromhex("8b11daf73cd05f2fe27809b74a7b4c65b1bb79cc1066bdf839d96b97e073c1a635d2ec048e0801b4a208118fdbbb63a516bab8755cc8d850862eeaa099540cd83621ff9db97b4ada857ef54c50715486217bd2ecb4517e05ab49380c041e159b"))


def test_vectors2():
    m1 = bytes([1, 2, 3, 40])
    m2 = bytes([5, 6, 70, 201])
    m3 = bytes([9, 10, 11, 12, 13])
    m4 = bytes([15, 63, 244, 92, 0, 1])

    sk1 = PrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    sk2 = PrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))

    sig1 = sk1.sign(m1)
    sig2 = sk2.sign(m2)
    sig3 = sk2.sign(m1)
    sig4 = sk1.sign(m3)
    sig5 = sk1.sign(m1)
    sig6 = sk1.sign(m4)

    sig_L = Signature.aggregate([sig1, sig2])
    sig_R = Signature.aggregate([sig3, sig4, sig5])
    assert(sig_L.verify())
    assert(sig_R.verify())

    sig_final = Signature.aggregate([sig_L, sig_R, sig6])
    assert(sig_final.serialize() == bytes.fromhex("07969958fbf82e65bd13ba0749990764cac81cf10d923af9fdd2723f1e3910c3fdb874a67f9d511bb7e4920f8c01232b12e2fb5e64a7c2d177a475dab5c3729ca1f580301ccdef809c57a8846890265d195b694fa414a2a3aa55c32837fddd80"))
    assert(sig_final.verify())
    quotient = sig_final.divide_by([sig2, sig5, sig6])
    assert(quotient.verify())
    assert(sig_final.verify())
    assert(quotient.serialize() == bytes.fromhex("8ebc8a73a2291e689ce51769ff87e517be6089fd0627b2ce3cd2f0ee1ce134b39c4da40928954175014e9bbe623d845d0bdba8bfd2a85af9507ddf145579480132b676f027381314d983a63842fcc7bf5c8c088461e3ebb04dcf86b431d6238f"))
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
    sig_R2 = Signature.aggregate([sig7, sig8])
    sig_final2 = Signature.aggregate([sig_final, sig_R2])
    quotient2 = sig_final2.divide_by([sig_R2])
    assert(quotient2.verify())
    assert(quotient2.serialize() == bytes.fromhex("06af6930bd06838f2e4b00b62911fb290245cce503ccf5bfc2901459897731dd08fc4c56dbde75a11677ccfbfa61ab8b14735fddc66a02b7aeebb54ab9a41488f89f641d83d4515c4dd20dfcf28cbbccb1472c327f0780be3a90c005c58a47d3"))


def test_vectors3():
    seed = bytes([1, 50, 6, 244, 24, 199, 1, 25])
    esk =  ExtendedPrivateKey.from_seed(seed)
    assert(esk.get_public_key().get_fingerprint() == 0xa4700b27)
    esk77 = esk.private_child(77 + 2**31)
    assert(esk77.get_public_key().get_fingerprint() == 0xa8063dcf)

    assert(esk.private_child(3)
              .private_child(17)
              .get_public_key()
              .get_fingerprint() == 0xff26a31f)

    assert(esk.get_extended_public_key()
              .public_child(3)
              .public_child(17)
              .get_public_key()
              .get_fingerprint() == 0xff26a31f)

def test_vectors4():
    sk1 = PrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    sk2 = PrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))

    pk1 = sk1.get_public_key()
    pk2 = sk2.get_public_key()

    m1 = bytes([7, 8, 9])
    m2 = bytes([10, 11, 12])

    sig9 = sk1.sign_prepend(m1)
    sig10 = sk2.sign_prepend(m2)

    assert(sig9.serialize() == bytes.fromhex("d2135ad358405d9f2d4e68dc253d64b6049a821797817cffa5aa804086a8fb7b135175bb7183750e3aa19513db1552180f0b0ffd513c322f1c0c30a0a9c179f6e275e0109d4db7fa3e09694190947b17d890f3d58fe0b1866ec4d4f5a59b16ed"))
    assert(sig10.serialize() == bytes.fromhex("cc58c982f9ee5817d4fbf22d529cfc6792b0fdcf2d2a8001686755868e10eb32b40e464e7fbfe30175a962f1972026f2087f0495ba6e293ac3cf271762cd6979b9413adc0ba7df153cf1f3faab6b893404c2e6d63351e48cd54e06e449965f08"))

    agg_sig = PrependSignature.aggregate([sig9, sig9, sig10])
    message_hashes =[hash256(m1), hash256(m1), hash256(m2)]
    pks = [pk1, pk1, pk2]
    assert(agg_sig.serialize() == bytes.fromhex("c37077684e735e62e3f1fd17772a236b4115d4b581387733d3b97cab08b90918c7e91c23380c93e54be345544026f93505d41e6000392b82ab3c8af1b2e3954b0ef3f62c52fc89f99e646ff546881120396c449856428e672178e5e0e14ec894"))
    assert(agg_sig.verify(message_hashes, pks))

def test1():
    seed = bytes([0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22])
    sk = PrivateKey.from_seed(seed)
    pk = sk.get_public_key()

    msg = bytes([100, 2, 254, 88, 90, 45, 23])

    sig = sk.sign(msg)

    sk_bytes = sk.serialize()
    pk_bytes = pk.serialize()
    sig_bytes = sig.serialize()

    sk = PrivateKey.from_bytes(sk_bytes)
    pk = PublicKey.from_bytes(pk_bytes)
    sig = Signature.from_bytes(sig_bytes)

    sig.set_aggregation_info(AggregationInfo.from_msg(pk, msg))
    ok = sig.verify()
    assert(ok)

    seed = bytes([1]) + seed[1:]
    sk1 = PrivateKey.from_seed(seed)
    seed = bytes([2]) + seed[1:]
    sk2 = PrivateKey.from_seed(seed)

    pk1 = sk1.get_public_key()
    sig1 = sk1.sign(msg)

    pk2 = sk2.get_public_key()
    sig2 = sk2.sign(msg)

    agg_sig = Signature.aggregate([sig1, sig2])
    agg_pubkey = PublicKey.aggregate([pk1, pk2], False)

    agg_sig.set_aggregation_info(AggregationInfo.from_msg(agg_pubkey, msg))
    assert(agg_sig.verify())

    seed = bytes([3]) + seed[1:]
    sk3 = PrivateKey.from_seed(seed)
    pk3 = sk3.get_public_key()
    msg2 = bytes([100, 2, 254, 88, 90, 45, 23])

    sig1 = sk1.sign(msg)
    sig2 = sk2.sign(msg)
    sig3 = sk3.sign(msg2)
    agg_sig_l = Signature.aggregate([sig1, sig2])
    agg_sig_final = Signature.aggregate([agg_sig_l, sig3])

    sig_bytes = agg_sig_final.serialize()

    agg_sig_final = Signature.from_bytes(sig_bytes)
    a1 = AggregationInfo.from_msg(pk1, msg)
    a2 = AggregationInfo.from_msg(pk2, msg)
    a3 = AggregationInfo.from_msg(pk3, msg2)
    a1a2 = AggregationInfo.merge_infos([a1, a2])
    a_final = AggregationInfo.merge_infos([a1a2, a3])
    print(a_final)
    agg_sig_final.set_aggregation_info(a_final)
    ok = agg_sig_final.verify()

    ok = agg_sig_l.verify()
    agg_sig_final = agg_sig_final.divide_by([agg_sig_l])

    ok = agg_sig_final.verify()

    agg_sk = PrivateKey.aggregate([sk1, sk2], [pk1, pk2])
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

    print(len(buffer1), buffer1)
    print(len(buffer2), buffer2)
    assert(sk_child.get_extended_public_key() == pk_child)


def test2():
    seed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    seed2 = bytes([1, 20, 102, 229, 1, 157])

    sk = PrivateKey.from_seed(seed)
    sk_cp = PrivateKey.from_seed(seed)
    sk2 = PrivateKey.from_seed(seed2)
    pk = sk.get_public_key()
    pk2 = sk2.get_public_key()
    assert(sk == sk_cp)
    assert(sk != sk2)
    assert(pk.get_fingerprint() == 0xddad59bb)

    sk2_ser = sk2.serialize()
    pk2_ser = pk2.serialize()
    pk2_copy = PublicKey.from_bytes(pk2_ser)
    assert(pk2 == pk2_copy)
    assert(pk != pk2)
    assert(len(pk2_ser) == 48)
    assert(len(sk2_ser) == 32)

    message = bytes("this is the message", "utf-8")
    sig = sk.sign(message)
    sig_ser = sig.serialize()
    sig_cp = Signature.from_bytes(sig_ser)
    a1 = AggregationInfo.from_msg(pk, message)
    sig_cp.set_aggregation_info(a1)
    a2 = sig_cp.get_aggregation_info()
    assert(a1 == a2)
    sig2 = sk2.sign(message)

    assert(len(sig_ser) == 96)
    assert(sig != sig2)
    assert(sig == sig_cp)

    sig_agg = Signature.aggregate([sig, sig2])

    result = sig_cp.verify()
    result2 = sig2.verify()
    result3 = sig_agg.verify()
    assert(result)
    assert(result2)
    assert(result3)
    sk2 = sk


def test_threshold_instance(T, N):
    commitments = []
    # fragments[i][j] = fragment held by player i,
    #                   received from player j
    fragments = [[None] * N for _ in range(N)]
    secrets = []

    # Step 1 : Threshold.create
    for player in range(N):
        secret_key, commi, frags = Threshold.create(T, N)
        for target, frag in enumerate(frags):
            fragments[target][player] = frag
        commitments.append(commi)
        secrets.append(secret_key)

    # Step 2 : Threshold.verify_secret_fragment
    for player_source in range(1, N+1):
        for player_target in range(1, N+1):
            assert Threshold.verify_secret_fragment(
                player_target, fragments[player_target - 1][player_source - 1],
                commitments[player_source - 1], T)

    # Step 3 : master_pubkey = PublicKey.aggregate(...)
    #          secret_share = PrivateKey.aggregate(...)
    master_pubkey = PublicKey.aggregate(
           [PublicKey.from_g1(cpoly[0].to_jacobian())
            for cpoly in commitments],
           False)

    secret_shares = [PrivateKey.aggregate(map(PrivateKey, row), None, False)
                     for row in fragments]

    master_privkey = PrivateKey.aggregate(secrets, None, False)
    msg = 'Test'
    signature_actual = master_privkey.sign(msg)

    # Step 4 : sig_share = Threshold.sign_with_coefficient(...)
    # Check every combination of T players
    for X in combinations(range(1, N+1), T):
        # X: a list of T indices like [1, 2, 5]

        # Check underlying secret key is correct
        r = Threshold.interpolate_at_zero(X,
                [secret_shares[x-1].value for x in X])
        secret_cand = PrivateKey(r)
        assert secret_cand == master_privkey

        # Check signatures
        signature_shares = [Threshold.sign_with_coefficient(secret_shares[x-1], msg, x, X)
                            for x in X]
        signature_cand = Signature.aggregate_sigs_simple(signature_shares)
        assert signature_cand == signature_actual

    # Check that the signature actually verifies the message
    agg_info = AggregationInfo.from_msg(master_pubkey, msg)
    signature_actual.set_aggregation_info(agg_info)
    assert signature_actual.verify()

    # Step 4b : Alternatively, we can add the lagrange coefficients
    # to 'unit' signatures.
    for X in combinations(range(1, N+1), T):
        # X: a list of T indices like [1, 2, 5]

        # Check signatures
        signature_shares = [secret_shares[x-1].sign(msg) for x in X]
        signature_cand = Threshold.aggregate_unit_sigs(signature_shares, X, T)
        assert signature_cand == signature_actual


def test_threshold():
    test_threshold_instance(1, 1)
    test_threshold_instance(1, 2)
    test_threshold_instance(2, 2)
    for T in range(1, 6):
        test_threshold_instance(T, 5)


test_threshold()
test_fields()
test_ec()
test_vectors()
test_vectors2()
test_vectors3()
test_vectors4()
test1()
test2()

print("\nAll tests passed.")


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
