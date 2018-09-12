# flake8: noqa: E501
from blspy import (BLSPrivateKey, BLSPublicKey,
                   BLSSignature, AggregationInfo,
                   ExtendedPrivateKey, BLS)


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
    ok = BLS.verify(sig)
    assert(ok)

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

    print(len(buffer1), buffer1)
    print(len(buffer2), buffer2)
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

    print(sk, sk2)
    print(pk, pk2)
    pk2_ser = pk2.serialize()
    print(pk2_ser)
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


def test_vectors():
    sk1 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5]))
    pk1 = sk1.get_public_key()
    sig1 = sk1.sign(bytes([7, 8, 9]))

    sk2 = BLSPrivateKey.from_seed(bytes([1, 2, 3, 4, 5, 6]))
    pk2 = sk2.get_public_key()
    sig2 = sk2.sign(bytes([7, 8, 9]))
    assert(sk1.serialize() == bytes.fromhex("022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e"))
    print("Pk1 finger:", hex(pk1.get_fingerprint()))
    assert(pk1.get_fingerprint() == 0x26d53247)
    assert(pk2.get_fingerprint() == 0x289bb56e)
    print("Sig 2 serialize", sig2.serialize().hex())
    assert(sig1.serialize() == bytes.fromhex("0f562d96ddabc780ce2ec4b00078e13ee265d7fb24fc2358f3aeb900d7e05f0c880388fe0abc4b460ab1ea3f843c0c28042503e005f357d3124151b87ba2df18b6a5d91afb9cd09cfed16876a25e505fe3bdfb8ccf1ba18be4ca35a095d81957"))
    assert(sig2.serialize() == bytes.fromhex("8388b5451e0d387fbcade62af7563705635f7eedaaf5c2d97ce2e116150f159256b7fe045f03a8a0013312bd5ea153130943caa0f409b6fac4850b0102e5f5f8ffc27ba900bd624317ba19cb19c5a681a083ef8167a4930bbc17aac8ea40bbd5"))

    agg_sig = BLS.aggregate_sigs([sig1, sig2])
    agg_pk = BLS.aggregate_pub_keys([pk1, pk2], True)
    agg_sk = BLS.aggregate_priv_keys([sk1, sk2], [pk1, pk2], True)
    assert(agg_sig.serialize() == bytes.fromhex("067d44075175669de7ebd5151c256d60b6a7ebbe06d0f680d135f26f912b7fbbe049a1b42fa910bbfa8a38e4466c4dbf02062fd347174015624b1885351104830354a89d307bc509489cd33fa0c79826672288250f27024b8ea0bcafcdcfd386"))
    assert(agg_sk.sign(bytes([7, 8, 9])).serialize() == agg_sig.serialize())

    assert(BLS.verify(sig1))
    assert(BLS.verify(agg_sig))

    agg_sig.set_aggregation_info(AggregationInfo.from_msg(agg_pk, bytes([7, 8, 9])))
    assert(BLS.verify(agg_sig))

    sig1.set_aggregation_info(sig2.get_aggregation_info())
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
    assert(sig_final.serialize() == bytes.fromhex("0309c9e3c32334ad6a4be270a2f0d8540b7edaec8ca887d6e177507985061b49601005c60859266a4aae8cb6347beedd14f4ab5a0ba0b7c54dee02cc3af16ded333c1fafa91d5022dee0b6b1403f4313870a9b96d555ad5ef16d4283c65fa173"))
    assert(BLS.verify(sig_final))
    quotient = sig_final.divide_by([sig2, sig5, sig6])
    assert(BLS.verify(quotient))
    assert(BLS.verify(sig_final))
    assert(quotient.serialize() == bytes.fromhex("0b86b6667163abf3893230f86d47379ee1a32b830640a22745e57746947174b7d56f1c0475d7e6968e7f9ca13a5b1c71116cfeb19e4679c76633c48f54d5da03204565456e269689980028ec68060cfcb006d8832ba45f133ad32a829c2392d5"))
    assert(quotient.divide_by([]) == quotient)
    try:
        quotient.divide_by([sig6])
        assert(False)  # Should fail due to not subset
    except Exception:
        pass
    sig_final.divide_by([sig1]) # Should not throw
    try:
        sig_final.divide_by([sig_L]) # Should throw due to not unique
        assert(False)  # Should fail due to not unique
    except Exception:
        pass

    # Divide by aggregate
    sig7 = sk2.sign(m3)
    sig8 = sk2.sign(m4)
    sig_R2 = BLS.aggregate_sigs([sig7, sig8])
    sig_final2 = BLS.aggregate_sigs([sig_final, sig_R2])
    quotient2 = sig_final2.divide_by([sig_R2])
    assert(BLS.verify(quotient2))
    assert(quotient2.serialize() == bytes.fromhex("9623063bd1f6d6aead6e337a0f53c8aff79e636bec2b01c68e530521d32a3476bcd741648d105d08c87b2a4094f047401541f74aa21b0d24e22362448cda036eb85727a48e2fa0cdf6f15290efdb176dbac1d220e597f175c32c3fa42f276ea6"))


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


def test_vectors3():
    seed = bytes([1, 50, 6, 244, 24, 199, 1, 25])
    esk = ExtendedPrivateKey.from_seed(seed)
    assert(esk.get_public_key().get_fingerprint() == 0xa4700b27)
    assert(esk.get_chain_code().serialize().hex() == "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3")
    esk77 = esk.private_child(77 + 2**31)
    assert(esk77.get_chain_code().serialize().hex() == "f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b")
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


test1()
test2()
test_vectors()
test_vectors2()
test_vectors3()

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
