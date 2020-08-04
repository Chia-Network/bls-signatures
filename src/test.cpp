
// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define CATCH_CONFIG_RUNNER
#include <thread>

#include "bls.hpp"
#include "catch.hpp"
#include "relic.h"
#include "relic_test.h"
#include "schemes.hpp"
#include "test-utils.hpp"
#include "hkdf.hpp"
#include "hdkeys.hpp"
using std::cout;
using std::endl;
using std::string;
using std::vector;

using namespace bls;

void TestHKDF(string ikm_hex, string salt_hex, string info_hex, string prk_expected_hex, string okm_expected_hex, int L) {
    vector<uint8_t> ikm = Util::HexToBytes(ikm_hex);
    vector<uint8_t> salt = Util::HexToBytes(salt_hex);
    vector<uint8_t> info = Util::HexToBytes(info_hex);
    vector<uint8_t> prk_expected = Util::HexToBytes(prk_expected_hex);
    vector<uint8_t> okm_expected = Util::HexToBytes(okm_expected_hex);
    uint8_t prk[32];
    HKDF256::Extract(prk, salt.data(), salt.size(), ikm.data(), ikm.size());
    uint8_t okm[L];
    HKDF256::Expand(okm, L, prk, info.data(), info.size());

    REQUIRE(32 == prk_expected.size());
    REQUIRE(L == okm_expected.size());

    for (size_t i=0; i < 32; i++) {
        REQUIRE(prk[i] == prk_expected[i]);
    }
    for (size_t i=0; i < L; i++) {
        REQUIRE(okm[i] == okm_expected[i]);
    }
}


TEST_CASE("HKDF") {
    // https://tools.ietf.org/html/rfc5869 test vectors
    SECTION("Test case 2") {
        TestHKDF("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 "000102030405060708090a0b0c",
                 "f0f1f2f3f4f5f6f7f8f9",
                 "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                 42
        );
    }
    SECTION("Test case 2") {
        TestHKDF("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f"
                 "202122232425262728292a2b2c2d2e2f"
                 "303132333435363738393a3b3c3d3e3f"
                 "404142434445464748494a4b4c4d4e4f", // 80 octets
                 "0x606162636465666768696a6b6c6d6e6f"
                 "707172737475767778797a7b7c7d7e7f"
                 "808182838485868788898a8b8c8d8e8f"
                 "909192939495969798999a9b9c9d9e9f"
                 "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", // 80 octets
                 "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                 "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                 "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                 "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                 "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", // 80 octets
                 "0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", // 32 octets
                 "0xb11e398dc80327a1c8e7f78c596a4934"
                 "4f012eda2d4efad8a050cc4c19afa97c"
                 "59045a99cac7827271cb41c65e590e09"
                 "da3275600c2f09b8367793a9aca3db71"
                 "cc30c58179ec3e87c14c01d5c1f3434f"
                 "1d87", // 82 octets
                 82
        );
    }
    SECTION("Test case 3") {
        TestHKDF("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 "",
                 "",
                 "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                 42
        );
    }
    SECTION("Works with multiple of 32") {
        // This generates exactly 64 bytes. Uses a 32 byte key and 4 byte salt as in EIP2333.
        TestHKDF("8704f9ac024139fe62511375cf9bc534c0507dcf00c41603ac935cd5943ce0b4b88599390de14e743ca2f56a73a04eae13aa3f3b969b39d8701e0d69a6f8d42f",
                 "53d8e19b",
                 "",
                 "eb01c9cd916653df76ffa61b6ab8a74e254ebfd9bfc43e624cc12a72b0373dee",
                 "8faabea85fc0c64e7ca86217cdc6dcdc88551c3244d56719e630a3521063082c46455c2fd5483811f9520a748f0099c1dfcfa52c54e1c22b5cdf70efb0f3c676",
                 64
        );
    }
}

void TestEIP2333(string seedHex, string masterSkHex, string childSkHex, uint32_t childIndex) {
    auto masterSk = Util::HexToBytes(masterSkHex);
    auto childSk = Util::HexToBytes(childSkHex);

    PrivateKey master = BasicSchemeMPL::KeyGen(Util::HexToBytes(seedHex));
    PrivateKey child = HDKeys::DeriveChildSk(master, childIndex);

    uint8_t master_arr[32];
    master.Serialize(master_arr);
    auto calculatedMaster = master.Serialize();
    auto calculatedChild = child.Serialize();

    REQUIRE(calculatedMaster.size() == 32);
    REQUIRE(calculatedChild.size() == 32);
    for (int i=0; i<32; i++) {
        REQUIRE(calculatedMaster[i] == masterSk[i]);
    }
    for (int i=0; i<32; i++) {
        REQUIRE(calculatedChild[i] == childSk[i]);
    }
}

TEST_CASE("EIP-2333 hardened HD keys") {
    // The comments in the test cases correspond to  integers that are converted to
    // bytes using python int.to_bytes(32, "big").hex(), since the EIP spec provides ints, but c++
    // does not support bigint by default
    SECTION("EIP-2333 Test case 1"){
        TestEIP2333("3141592653589793238462643383279502884197169399375105820974944592",
                    // 36167147331491996618072159372207345412841461318189449162487002442599770291484
                    "4ff5e145590ed7b71e577bb04032396d1619ff41cb4e350053ed2dce8d1efd1c",
                    // 41787458189896526028601807066547832426569899195138584349427756863968330588237
                    "5c62dcf9654481292aafa3348f1d1b0017bbfb44d6881d26d2b17836b38f204d",
                    3141592653
        );
    }
    SECTION("EIP-2333 Test case 2"){
        TestEIP2333("0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
                    // 13904094584487173309420026178174172335998687531503061311232927109397516192843
                    "1ebd704b86732c3f05f30563dee6189838e73998ebc9c209ccff422adee10c4b",
                    // 12482522899285304316694838079579801944734479969002030150864436005368716366140
                    "1b98db8b24296038eae3f64c25d693a269ef1e4d7ae0f691c572a46cf3c0913c",
                    4294967295
        );
    }
    SECTION("EIP-2333 Test case 3"){
        TestEIP2333("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                    // 44010626067374404458092393860968061149521094673473131545188652121635313364506
                    "614d21b10c0e4996ac0608e0e7452d5720d95d20fe03c59a3321000a42432e1a",
                    // 4011524214304750350566588165922015929937602165683407445189263506512578573606
                    "08de7136e4afc56ae3ec03b20517d9c1232705a747f588fd17832f36ae337526",
                    42
        );
    }
    SECTION("EIP-2333 Test vector with intermediate values"){
        TestEIP2333("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                    // 5399117110774477986698372024995405256382522670366369834617409486544348441851
                    "0x0befcabff4a664461cc8f190cdd51c05621eb2837c71a1362df5b465a674ecfb",
                    // 11812940737387919040225825939013910852517748782307378293770044673328955938106
                    "1a1de3346883401f1e3b2281be5774080edb8e5ebe6f776b0f7af9fea942553a",
                    0
        );
    }
}

TEST_CASE("Unhardened HD keys") {
    SECTION("Should match derivation through private and public keys"){
        const vector<uint8_t> seed = {1, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29};

        PrivateKey sk = BasicSchemeMPL::KeyGen(seed);
        G1Element pk = sk.GetG1Element();

        PrivateKey childSk = BasicSchemeMPL::DeriveChildSkUnhardened(sk, 42);
        G1Element childPk = BasicSchemeMPL::DeriveChildPkUnhardened(pk, 42);

        REQUIRE(childSk.GetG1Element() == childPk);

        PrivateKey grandchildSk = BasicSchemeMPL::DeriveChildSkUnhardened(childSk, 12142);
        G1Element grandcihldPk = BasicSchemeMPL::DeriveChildPkUnhardened(childPk, 12142);

        REQUIRE(grandchildSk.GetG1Element() == grandcihldPk);
    }

    SECTION("Should derive public child from parent") {
        const vector<uint8_t> seed = {2, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29};

        PrivateKey sk = BasicSchemeMPL::KeyGen(seed);
        G1Element pk = sk.GetG1Element();

        PrivateKey childSk = BasicSchemeMPL::DeriveChildSkUnhardened(sk, 42);
        G1Element childPk = BasicSchemeMPL::DeriveChildPkUnhardened(pk, 42);

        PrivateKey childSkHardened = BasicSchemeMPL::DeriveChildSk(sk, 42);
        REQUIRE(childSk.GetG1Element() == childPk);
        REQUIRE(childSkHardened != childSk);
        REQUIRE(childSkHardened.GetG1Element() != childPk);
    }
}

TEST_CASE("Algorand IETF test vectors") {
    SECTION ("Pyecc vector") {
        string sig1BasicHex = "96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99";
        string sk = "0x0101010101010101010101010101010101010101010101010101010101010101";
        std::vector<uint8_t> msg = {3, 1, 4, 1, 5, 9};
        auto skobj = PrivateKey::FromBytes(Util::HexToBytes(sk).data());
        G2Element sig = BasicSchemeMPL::Sign(skobj, msg);
        vector<uint8_t> sig1;
        for (const uint8_t byte : Util::HexToBytes(sig1BasicHex)) {
            sig1.push_back(byte);
        }
        REQUIRE(sig == G2Element::FromByteVector(sig1));
    }
}


TEST_CASE("Chia test vectors") {
    SECTION("Chia test vectors 1 (Basic)") {
        vector<uint8_t> seed1(32, 0x00);  // All 0s
        vector<uint8_t> seed2(32, 0x01);  // All 1s
        vector<uint8_t> message1 = {7, 8, 9};
        vector<uint8_t> message2 = {10, 11, 12};

        PrivateKey sk1 = BasicSchemeMPL::KeyGen(seed1);
        G1Element pk1 = sk1.GetG1Element();
        G2Element sig1 = BasicSchemeMPL::Sign(sk1, message1);


        PrivateKey sk2 = BasicSchemeMPL::KeyGen(seed2);
        G1Element pk2 = sk2.GetG1Element();
        G2Element sig2 = BasicSchemeMPL::Sign(sk2, message2);

        REQUIRE(pk1.GetFingerprint() == 0xb40dd58a);
        REQUIRE(pk2.GetFingerprint() == 0xb839add1);

        REQUIRE(
            Util::HexStr(sig1.Serialize()) ==
            "b8faa6d6a3881c9fdbad803b170d70ca5cbf1e6ba5a586262df368c75acd1d1f"
            "fa3ab6ee21c71f844494659878f5eb230c958dd576b08b8564aad2ee0992e85a"
            "1e565f299cd53a285de729937f70dc176a1f01432129bb2b94d3d5031f8065a1");
        REQUIRE(
            Util::HexStr(sk1.Serialize()) ==
            "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604");
        REQUIRE(
            Util::HexStr(pk1.Serialize()) ==
            "85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911e"
            "f1e2e08749bddbf165352");

        REQUIRE(
            Util::HexStr(sig2.Serialize()) ==
            "a9c4d3e689b82c7ec7e838dac2380cb014f9a08f6cd6ba044c263746e39a8f7a60ffee4afb7"
            "8f146c2e421360784d58f0029491e3bd8ab84f0011d258471ba4e87059de295d9aba845c044e"
            "e83f6cf2411efd379ef38bf4cf41d5f3c0ae1205d");

        G2Element aggSig1 = BasicSchemeMPL::Aggregate({sig1, sig2});

        REQUIRE(
            Util::HexStr(aggSig1.Serialize()) ==
            "aee003c8cdaf3531b6b0ca354031b0819f7586b5846796615aee8108fec75ef838d181f9d24"
            "4a94d195d7b0231d4afcf06f27f0cc4d3c72162545c240de7d5034a7ef3a2a03c0159de982fb"
            "c2e7790aeb455e27beae91d64e077c70b5506dea3");

        REQUIRE(BasicSchemeMPL::AggregateVerify({pk1, pk2}, {message1, message2}, aggSig1));

        vector<uint8_t> message3 = {1, 2, 3};
        vector<uint8_t> message4 = {1, 2, 3, 4};
        vector<uint8_t> message5 = {1, 2};

        G2Element sig3 = BasicSchemeMPL::Sign(sk1, message3);
        G2Element sig4 = BasicSchemeMPL::Sign(sk1, message4);
        G2Element sig5 = BasicSchemeMPL::Sign(sk2, message5);

        G2Element aggSig2 = BasicSchemeMPL::Aggregate({sig3, sig4, sig5});

        REQUIRE(BasicSchemeMPL::AggregateVerify({pk1, pk1, pk2}, {message3, message4, message5}, aggSig2));
        REQUIRE(
            Util::HexStr(aggSig2.Serialize()) ==
            "a0b1378d518bea4d1100adbc7bdbc4ff64f2c219ed6395cd36fe5d2aa44a4b8e710b607afd9"
            "65e505a5ac3283291b75413d09478ab4b5cfbafbeea366de2d0c0bcf61deddaa521f6020460f"
            "d547ab37659ae207968b545727beba0a3c5572b9c");
    }

    // SECTION("Test vector 2")
    // {
    //     uint8_t message1[4] = {1, 2, 3, 40};
    //     uint8_t message2[4] = {5, 6, 70, 201};
    //     uint8_t message3[5] = {9, 10, 11, 12, 13};
    //     uint8_t message4[6] = {15, 63, 244, 92, 0, 1};

    //     uint8_t seed1[5] = {1, 2, 3, 4, 5};
    //     uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};

    //     PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
    //     PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));

    //     G1Element pk1 = sk1.GetG1Element();
    //     G1Element pk2 = sk2.GetG1Element();

    //     G2Element sig1 = sk1.Sign(message1, sizeof(message1));
    //     G2Element sig2 = sk2.Sign(message2, sizeof(message2));
    //     G2Element sig3 = sk2.Sign(message1, sizeof(message1));
    //     G2Element sig4 = sk1.Sign(message3, sizeof(message3));
    //     G2Element sig5 = sk1.Sign(message1, sizeof(message1));
    //     G2Element sig6 = sk1.Sign(message4, sizeof(message4));

    //     std::vector<G2Element> const sigsL = {sig1, sig2};
    //     const G2Element aggSigL = G2Element::Aggregate(sigsL);

    //     std::vector<G2Element> const sigsR = {sig3, sig4, sig5};
    //     const G2Element aggSigR = G2Element::Aggregate(sigsR);

    //     std::vector<G2Element> sigs = {aggSigL, aggSigR, sig6};

    //     G2Element aggSig = G2Element::Aggregate(sigs);

    //     REQUIRE(aggSig.Verify());

    //     uint8_t buf[G2Element::G2Element_SIZE];
    //     aggSig.Serialize(buf);
    //     REQUIRE(
    //         Util::HexStr(buf, G2Element::G2Element_SIZE) ==
    //         "07969958fbf82e65bd13ba0749990764cac81cf10d923af9fdd2723f1e3910c3fd"
    //         "b874a67f9d511bb7e4920f8c01232b12e2fb5e64a7c2d177a475dab5c3729ca1f5"
    //         "80301ccdef809c57a8846890265d195b694fa414a2a3aa55c32837fddd80");
    //     vector<G2Element> G2Elements_to_divide = {sig2, sig5, sig6};
    //     G2Element quotient = aggSig.DivideBy(G2Elements_to_divide);
    //     aggSig.DivideBy(G2Elements_to_divide);

    //     quotient.Serialize(buf);
    //     REQUIRE(
    //         Util::HexStr(buf, G2Element::G2Element_SIZE) ==
    //         "8ebc8a73a2291e689ce51769ff87e517be6089fd0627b2ce3cd2f0ee1ce134b39c"
    //         "4da40928954175014e9bbe623d845d0bdba8bfd2a85af9507ddf145579480132b6"
    //         "76f027381314d983a63842fcc7bf5c8c088461e3ebb04dcf86b431d6238f");

    //     REQUIRE(quotient.Verify());
    //     REQUIRE(quotient.DivideBy(vector<G2Element>()) == quotient);
    //     G2Elements_to_divide = {sig6};
    //     REQUIRE_THROWS(quotient.DivideBy(G2Elements_to_divide));

    //     // Should not throw
    //     G2Elements_to_divide = {sig1};
    //     aggSig.DivideBy(G2Elements_to_divide);

    //     // Should throw due to not unique
    //     G2Elements_to_divide = {aggSigL};
    //     REQUIRE_THROWS(aggSig.DivideBy(G2Elements_to_divide));

    //     G2Element sig7 = sk2.Sign(message3, sizeof(message3));
    //     G2Element sig8 = sk2.Sign(message4, sizeof(message4));

    //     // Divide by aggregate
    //     std::vector<G2Element> sigsR2 = {sig7, sig8};
    //     G2Element aggSigR2 = G2Element::Aggregate(sigsR2);
    //     std::vector<G2Element> sigsFinal2 = {aggSig, aggSigR2};
    //     G2Element aggSig2 = G2Element::Aggregate(sigsFinal2);
    //     std::vector<G2Element> divisorFinal2 = {aggSigR2};
    //     G2Element quotient2 = aggSig2.DivideBy(divisorFinal2);

    //     REQUIRE(quotient2.Verify());
    //     quotient2.Serialize(buf);
    //     REQUIRE(
    //         Util::HexStr(buf, G2Element::G2Element_SIZE) ==
    //         "06af6930bd06838f2e4b00b62911fb290245cce503ccf5bfc2901459897731dd08"
    //         "fc4c56dbde75a11677ccfbfa61ab8b14735fddc66a02b7aeebb54ab9a41488f89f"
    //         "641d83d4515c4dd20dfcf28cbbccb1472c327f0780be3a90c005c58a47d3");
    // }

    // SECTION("Test vector 3")
    // {
    //     uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
    //     ExtendedPrivateKey esk =
    //         ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
    //     REQUIRE(esk.GetG1Element().GetFingerprint() == 0xa4700b27);
    //     uint8_t chainCode[32];
    //     esk.GetChainCode().Serialize(chainCode);
    //     REQUIRE(
    //         Util::HexStr(chainCode, 32) ==
    //         "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3");

    //     ExtendedPrivateKey esk77 = esk.PrivateChild(77 + (1 << 31));
    //     esk77.GetChainCode().Serialize(chainCode);
    //     REQUIRE(
    //         Util::HexStr(chainCode, 32) ==
    //         "f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b");
    //     REQUIRE(
    //         esk77.GetPrivateKey().GetG1Element().GetFingerprint() ==
    //         0xa8063dcf);

    //     REQUIRE(
    //         esk.PrivateChild(3)
    //             .PrivateChild(17)
    //             .GetG1Element()
    //             .GetFingerprint() == 0xff26a31f);
    //     REQUIRE(
    //         esk.GetExtendedG1Element()
    //             .PublicChild(3)
    //             .PublicChild(17)
    //             .GetG1Element()
    //             .GetFingerprint() == 0xff26a31f);
    // }

    // SECTION("Test vector 4")
    // {
    //     uint8_t seed1[5] = {1, 2, 3, 4, 5};
    //     uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};
    //     uint8_t message1[3] = {7, 8, 9};
    //     uint8_t message2[3] = {10, 11, 12};

    //     PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
    //     G1Element pk1 = sk1.GetG1Element();

    //     PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));
    //     G1Element pk2 = sk2.GetG1Element();

    //     PrependG2Element sig9 = sk1.SignPrepend(message1, sizeof(message1));
    //     PrependG2Element sig10 = sk2.SignPrepend(message2, sizeof(message2));

    //     uint8_t buf[G2Element::G2Element_SIZE];
    //     sig9.Serialize(buf);
    //     REQUIRE(
    //         Util::HexStr(buf, G2Element::G2Element_SIZE) ==
    //         "d2135ad358405d9f2d4e68dc253d64b6049a821797817cffa5aa804086a8fb7b13"
    //         "5175bb7183750e3aa19513db1552180f0b0ffd513c322f1c0c30a0a9c179f6e275"
    //         "e0109d4db7fa3e09694190947b17d890f3d58fe0b1866ec4d4f5a59b16ed");
    //     sig10.Serialize(buf);
    //     REQUIRE(
    //         Util::HexStr(buf, G2Element::G2Element_SIZE) ==
    //         "cc58c982f9ee5817d4fbf22d529cfc6792b0fdcf2d2a8001686755868e10eb32b4"
    //         "0e464e7fbfe30175a962f1972026f2087f0495ba6e293ac3cf271762cd6979b941"
    //         "3adc0ba7df153cf1f3faab6b893404c2e6d63351e48cd54e06e449965f08");

    //     uint8_t messageHash1[BLS::MESSAGE_HASH_LEN];
    //     uint8_t messageHash2[BLS::MESSAGE_HASH_LEN];
    //     Util::Hash256(messageHash1, message1, sizeof(message1));
    //     Util::Hash256(messageHash2, message2, sizeof(message2));
    //     vector<const uint8_t*> messageHashes1 = {messageHash1};
    //     vector<const uint8_t*> messageHashes2 = {messageHash2};
    //     vector<const uint8_t*> messageHashes = {
    //         messageHash1, messageHash1, messageHash2};
    //     vector<G1Element> pks = {pk1, pk1, pk2};

    //     vector<PrependG2Element> sigs = {sig9, sig9, sig10};
    //     PrependG2Element agg = PrependG2Element::Aggregate(sigs);

    //     agg.Serialize(buf);
    //     REQUIRE(
    //         Util::HexStr(buf, G2Element::G2Element_SIZE) ==
    //         "c37077684e735e62e3f1fd17772a236b4115d4b581387733d3b97cab08b90918c7"
    //         "e91c23380c93e54be345544026f93505d41e6000392b82ab3c8af1b2e3954b0ef3"
    //         "f62c52fc89f99e646ff546881120396c449856428e672178e5e0e14ec894");

    //     REQUIRE(agg.Verify(messageHashes, pks));
    // }
}

/*
TEST_CASE("Key generation")
{
    SECTION("Should generate a keypair from a seed")
    {
        uint8_t seed[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

        PrivateKey sk = PrivateKey::FromSeed(seed, sizeof(seed));
        G1Element pk = sk.GetG1Element();
        REQUIRE(core_get()->code == RLC_OK);
        REQUIRE(pk.GetFingerprint() == 0xddad59bb);
    }
}

TEST_CASE("Error handling")
{
    SECTION("Should throw on a bad private key")
    {
        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        uint8_t* skData = Util::SecAlloc<uint8_t>(G2Element::G2Element_SIZE);
        sk1.Serialize(skData);
        skData[0] = 255;
        REQUIRE_THROWS(PrivateKey::FromBytes(skData));

        Util::SecFree(skData);
    }

    SECTION("Should throw on a bad public key")
    {
        uint8_t buf[G1Element::PUBLIC_KEY_SIZE] = {0};
        std::set<int> invalid = {1, 2, 3, 4};

        for (int i = 0; i < 10; i++) {
            buf[0] = (uint8_t)i;
            try {
                G1Element::FromBytes(buf);
                REQUIRE(invalid.count(i) == 0);
            } catch (std::invalid_argument& s) {
                REQUIRE(invalid.count(i) != 0);
            }
        }
    }

    SECTION("Should throw on a bad G2Element")
    {
        uint8_t buf[G2Element::G2Element_SIZE] = {0};
        std::set<int> invalid = {0, 1, 2, 3, 5, 6, 7, 8};

        for (int i = 0; i < 10; i++) {
            buf[0] = (uint8_t)i;
            try {
                G2Element::FromBytes(buf);
                REQUIRE(invalid.count(i) == 0);
            } catch (std::invalid_argument& s) {
                REQUIRE(invalid.count(i) != 0);
            }
        }
    }

    SECTION("Error handling should be thread safe")
    {
        core_get()->code = 10;
        REQUIRE(core_get()->code == 10);

        ctx_t* ctx1 = core_get();
        bool ctxError = false;

        // spawn a thread and make sure it uses a different context
        std::thread([&]() {
            if (ctx1 == core_get()) {
                ctxError = true;
            }
            if (core_get()->code != RLC_OK) {
                ctxError = true;
            }
            // this should not modify the code of the main thread
            core_get()->code = 1;
        }).join();

        REQUIRE(!ctxError);

        // other thread should not modify code
        REQUIRE(core_get()->code == 10);

        // reset so that future test cases don't fail
        core_get()->code = RLC_OK;
    }
}

TEST_CASE("Util tests")
{
    SECTION("Should convert an int to four bytes")
    {
        uint32_t x = 1024;
        uint8_t expected[4] = {0x00, 0x00, 0x04, 0x00};
        uint8_t result[4];
        Util::IntToFourBytes(result, x);
        REQUIRE(result[0] == expected[0]);
        REQUIRE(result[1] == expected[1]);
        REQUIRE(result[2] == expected[2]);
        REQUIRE(result[3] == expected[3]);
        uint32_t again = Util::FourBytesToInt(result);
        REQUIRE(again == x);
    }

    SECTION("Should calculate public key fingerprints")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        uint32_t fingerprint = esk.GetG1Element().GetFingerprint();
        REQUIRE(fingerprint == 0xa4700b27);
    }
}

TEST_CASE("G2Elements")
{
    SECTION("Should sign and verify")
    {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[6] = {28, 20, 102, 229, 1, 157};
        PrivateKey sk1 = PrivateKey::FromSeed(seed, sizeof(seed));
        G1Element pk1 = sk1.GetG1Element();
        G2Element sig1 = sk1.Sign(message1, sizeof(message1));

        sig1.SetAggregationInfo(
            AggregationInfo::FromMsg(pk1, message1, sizeof(message1)));
        REQUIRE(sig1.Verify());

        uint8_t hash[32];
        Util::Hash256(hash, message1, 7);
        G2Element sig2 = sk1.SignPrehashed(hash);
        sig2.SetAggregationInfo(
            AggregationInfo::FromMsg(pk1, message1, sizeof(message1)));
        REQUIRE(sig1 == sig2);
        REQUIRE(sig2.Verify());

        // Hashing to g1
        uint8_t mapMsg[0] = {};
        g1_t result;
        uint8_t buf[49];
        ep_map_ft(result, mapMsg, 0);
        g1_write_bin(buf, 49, result, 1);
        REQUIRE(
            Util::HexStr(buf + 1, 48) ==
            "12fc5ad5a2fbe9d4b6eb0bc16d530e5f263b6d59cbaf26c3f2831962924aa588ab"
            "84d46cc80d3a433ce064adb307f256");
    }

    SECTION("Should use copy constructor")
    {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();
        PrivateKey sk2 = PrivateKey(sk1);

        uint8_t skBytes[PrivateKey::PRIVATE_KEY_SIZE];
        sk2.Serialize(skBytes);
        PrivateKey sk4 = PrivateKey::FromBytes(skBytes);

        G1Element pk2 = G1Element(pk1);
        G2Element sig1 = sk4.Sign(message1, sizeof(message1));
        G2Element sig2 = G2Element(sig1);

        REQUIRE(sig2.Verify());
    }

    SECTION("Should use operators")
    {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey(sk1);
        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        G1Element pk1 = sk1.GetG1Element();
        G1Element pk2 = sk2.GetG1Element();
        G1Element pk3 = G1Element(pk2);
        G1Element pk4 = sk3.GetG1Element();
        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk1.Sign(message1, sizeof(message1));
        G2Element sig3 = sk2.Sign(message1, sizeof(message1));
        G2Element sig4 = sk3.Sign(message1, sizeof(message1));

        REQUIRE(sk1 == sk2);
        REQUIRE(sk1 != sk3);
        REQUIRE(pk1 == pk2);
        REQUIRE(pk2 == pk3);
        REQUIRE(pk1 != pk4);
        REQUIRE(sig1 == sig2);
        REQUIRE(sig2 == sig3);
        REQUIRE(sig3 != sig4);

        REQUIRE(pk1.Serialize() == pk2.Serialize());
        REQUIRE(sig1.Serialize() == sig2.Serialize());
    }

    SECTION("Should serialize and deserialize")
    {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        uint8_t* skData = Util::SecAlloc<uint8_t>(G2Element::G2Element_SIZE);
        sk1.Serialize(skData);
        PrivateKey sk2 = PrivateKey::FromBytes(skData);
        REQUIRE(sk1 == sk2);

        uint8_t pkData[G1Element::PUBLIC_KEY_SIZE];
        pk1.Serialize(pkData);

        G1Element pk2 = G1Element::FromBytes(pkData);
        REQUIRE(pk1 == pk2);

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));

        uint8_t sigData[G2Element::G2Element_SIZE];
        sig1.Serialize(sigData);

        G2Element sig2 = G2Element::FromBytes(sigData);
        REQUIRE(sig1 == sig2);
        sig2.SetAggregationInfo(
            AggregationInfo::FromMsg(pk2, message1, sizeof(message1)));

        REQUIRE(sig2.Verify());
        Util::SecFree(skData);

        InsecureG2Element sig3 = InsecureG2Element::FromBytes(sigData);
        REQUIRE(G2Element::FromInsecureSig(sig3) == sig2);
    }

    SECTION("Should not validate a bad sig")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 22};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);

        G1Element pk1 = sk1.GetG1Element();
        G1Element pk2 = sk2.GetG1Element();

        G2Element sig2 = sk2.Sign(message1, sizeof(message1));
        sig2.SetAggregationInfo(
            AggregationInfo::FromMsg(pk1, message1, sizeof(message1)));

        REQUIRE(sig2.Verify() == false);
    }

    SECTION("Should insecurely aggregate and verify aggregate same message")
    {
        uint8_t message[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t hash[BLS::MESSAGE_HASH_LEN];

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        Util::Hash256(hash, message, sizeof(message));

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);

        InsecureG2Element sig1 = sk1.SignInsecure(message, sizeof(message));
        InsecureG2Element sig2 = sk2.SignInsecure(message, sizeof(message));
        REQUIRE(sig1 != sig2);
        REQUIRE(sig1.Verify({hash}, {sk1.GetG1Element()}));
        REQUIRE(sig2.Verify({hash}, {sk2.GetG1Element()}));

        std::vector<InsecureG2Element> const sigs = {sig1, sig2};
        std::vector<G1Element> const pks = {sk1.GetG1Element(),
                                            sk2.GetG1Element()};
        InsecureG2Element aggSig = InsecureG2Element::Aggregate(sigs);
        G1Element aggPk = G1Element::AggregateInsecure(pks);
        REQUIRE(aggSig.Verify({hash}, {aggPk}));
    }

    SECTION("Should insecurely aggregate and verify aggregate diff messages")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[8] = {100, 2, 254, 88, 90, 45, 24, 1};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);

        uint8_t hash1[BLS::MESSAGE_HASH_LEN];
        uint8_t hash2[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(hash1, message1, sizeof(message1));
        Util::Hash256(hash2, message2, sizeof(message2));

        InsecureG2Element sig1 = sk1.SignInsecurePrehashed(hash1);
        InsecureG2Element sig2 = sk2.SignInsecurePrehashed(hash2);
        REQUIRE(sig1 != sig2);
        REQUIRE(sig1.Verify({hash1}, {sk1.GetG1Element()}));
        REQUIRE(sig2.Verify({hash2}, {sk2.GetG1Element()}));

        std::vector<InsecureG2Element> const sigs = {sig1, sig2};
        std::vector<G1Element> const pks = {sk1.GetG1Element(),
                                            sk2.GetG1Element()};
        InsecureG2Element aggSig = InsecureG2Element::Aggregate(sigs);

        // same message verification should fail
        G1Element aggPk = G1Element::AggregateInsecure(pks);
        REQUIRE(!aggSig.Verify({hash1}, {aggPk}));
        REQUIRE(!aggSig.Verify({hash2}, {aggPk}));

        // diff message verification should succeed
        std::vector<const uint8_t*> hashes = {hash1, hash2};
        REQUIRE(aggSig.Verify(hashes, pks));
    }

    SECTION("Should securely aggregate and verify aggregate")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[7] = {192, 29, 2, 0, 0, 45, 23};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);

        G1Element pk1 = sk1.GetG1Element();
        G1Element pk2 = sk2.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message2, sizeof(message2));

        std::vector<G2Element> const sigs = {sig1, sig2};
        G2Element aggSig = G2Element::Aggregate(sigs);

        G2Element sig3 = sk1.Sign(message1, sizeof(message1));
        G2Element sig4 = sk2.Sign(message2, sizeof(message2));

        std::vector<G2Element> const sigs2 = {sig3, sig4};
        G2Element aggSig2 = G2Element::Aggregate(sigs2);
        REQUIRE(sig1 == sig3);
        REQUIRE(sig2 == sig4);
        REQUIRE(aggSig == aggSig2);
        REQUIRE(sig1 != sig2);

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should securely aggregate many G2Elements, diff message")
    {
        std::vector<PrivateKey> sks;
        std::vector<G2Element> sigs;

        for (int i = 0; i < 80; i++) {
            uint8_t* message = new uint8_t[8];
            message[0] = 0;
            message[1] = 100;
            message[2] = 2;
            message[3] = 59;
            message[4] = 255;
            message[5] = 92;
            message[6] = 5;
            message[7] = i;
            uint8_t seed[32];
            getRandomSeed(seed);
            const PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            const G1Element pk = sk.GetG1Element();
            sks.push_back(sk);
            sigs.push_back(sk.Sign(message, sizeof(message)));
            delete[] message;
        }

        G2Element aggSig = G2Element::Aggregate(sigs);

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should insecurely aggregate many G2Elements, diff message")
    {
        std::vector<PrivateKey> sks;
        std::vector<G1Element> pks;
        std::vector<InsecureG2Element> sigs;
        std::vector<const uint8_t*> hashes;

        for (int i = 0; i < 80; i++) {
            uint8_t* message = new uint8_t[8];
            uint8_t* hash = new uint8_t[BLS::MESSAGE_HASH_LEN];
            message[0] = 0;
            message[1] = 100;
            message[2] = 2;
            message[3] = 59;
            message[4] = 255;
            message[5] = 92;
            message[6] = 5;
            message[7] = i;
            Util::Hash256(hash, message, 8);
            hashes.push_back(hash);
            uint8_t seed[32];
            getRandomSeed(seed);
            const PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            const G1Element pk = sk.GetG1Element();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.SignInsecurePrehashed(hash));
            delete[] message;
        }

        InsecureG2Element aggSig = InsecureG2Element::Aggregate(sigs);

        REQUIRE(aggSig.Verify(hashes, pks));
        std::swap(pks[0], pks[1]);
        REQUIRE(!aggSig.Verify(hashes, pks));
        std::swap(hashes[0], hashes[1]);
        REQUIRE(aggSig.Verify(hashes, pks));

        for (auto& p : hashes) {
            delete[] p;
        }
    }

    SECTION("Should securely aggregate same message")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        G1Element pk2 = sk2.GetG1Element();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        G1Element pk3 = sk3.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message1, sizeof(message1));
        G2Element sig3 = sk3.Sign(message1, sizeof(message1));

        std::vector<G2Element> const sigs = {sig1, sig2, sig3};
        std::vector<G1Element> const pubKeys = {pk1, pk2, pk3};
        G2Element aggSig = G2Element::Aggregate(sigs);

        const G1Element aggPubKey = G1Element::Aggregate(pubKeys);
        aggSig.SetAggregationInfo(
            AggregationInfo::FromMsg(aggPubKey, message1, sizeof(message1)));
        REQUIRE(aggSig.Verify());
    }

    SECTION("Should securely divide G2Elements")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        G1Element pk2 = sk2.GetG1Element();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        G1Element pk3 = sk3.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message1, sizeof(message1));
        G2Element sig3 = sk3.Sign(message1, sizeof(message1));

        std::vector<G2Element> sigs = {sig1, sig2, sig3};
        G2Element aggSig = G2Element::Aggregate(sigs);

        REQUIRE(sig2.Verify());
        REQUIRE(sig3.Verify());
        std::vector<G2Element> divisorSigs = {sig2, sig3};

        REQUIRE(aggSig.Verify());

        REQUIRE(aggSig.GetAggregationInfo()->GetPubKeys().size() == 3);
        const G2Element aggSig2 = aggSig.DivideBy(divisorSigs);
        REQUIRE(aggSig.GetAggregationInfo()->GetPubKeys().size() == 3);
        REQUIRE(aggSig2.GetAggregationInfo()->GetPubKeys().size() == 1);

        REQUIRE(aggSig.Verify());
        REQUIRE(aggSig2.Verify());
    }

    SECTION("Should securely divide aggregate G2Elements")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[7] = {92, 20, 5, 89, 91, 15, 105};
        uint8_t message3[7] = {200, 10, 10, 159, 4, 15, 24};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);
        uint8_t seed4[32];
        getRandomSeed(seed4);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        G1Element pk2 = sk2.GetG1Element();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        G1Element pk3 = sk3.GetG1Element();

        PrivateKey sk4 = PrivateKey::FromSeed(seed4, 32);
        G1Element pk4 = sk4.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message1, sizeof(message1));
        G2Element sig3 = sk3.Sign(message1, sizeof(message1));
        G2Element sig4 = sk4.Sign(message2, sizeof(message2));
        G2Element sig5 = sk4.Sign(message1, sizeof(message1));
        G2Element sig6 = sk2.Sign(message3, sizeof(message3));

        std::vector<G2Element> sigsL = {sig1, sig2};
        std::vector<G2Element> sigsC = {sig3, sig4};
        std::vector<G2Element> sigsR = {sig5, sig6};
        G2Element aggSigL = G2Element::Aggregate(sigsL);
        G2Element aggSigC = G2Element::Aggregate(sigsC);
        G2Element aggSigR = G2Element::Aggregate(sigsR);

        std::vector<G2Element> sigsL2 = {aggSigL, aggSigC};
        G2Element aggSigL2 = G2Element::Aggregate(sigsL2);

        std::vector<G2Element> sigsFinal = {aggSigL2, aggSigR};
        G2Element aggSigFinal = G2Element::Aggregate(sigsFinal);

        REQUIRE(aggSigFinal.Verify());
        REQUIRE(aggSigFinal.GetAggregationInfo()->GetPubKeys().size() == 6);
        std::vector<G2Element> divisorSigs = {aggSigL, sig6};
        aggSigFinal = aggSigFinal.DivideBy(divisorSigs);
        REQUIRE(aggSigFinal.GetAggregationInfo()->GetPubKeys().size() == 3);
        REQUIRE(aggSigFinal.Verify());

        // Throws when the m/pk pair is not unique within the aggregate (sig1
        // is in both aggSigL2 and sig1.
        std::vector<G2Element> sigsFinal2 = {aggSigL2, aggSigR, sig1};
        G2Element aggSigFinal2 = G2Element::Aggregate(sigsFinal2);
        std::vector<G2Element> divisorSigs2 = {aggSigL};
        std::vector<G2Element> divisorSigs3 = {sig6};
        aggSigFinal2 = aggSigFinal2.DivideBy(divisorSigs3);
        REQUIRE_THROWS(aggSigFinal2.DivideBy(divisorSigs));
    }

    SECTION("Should insecurely aggregate many sigs, same message")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t hash1[BLS::MESSAGE_HASH_LEN];

        std::vector<PrivateKey> sks;
        std::vector<G1Element> pks;
        std::vector<InsecureG2Element> sigs;

        Util::Hash256(hash1, message1, sizeof(message1));

        for (int i = 0; i < 70; i++) {
            uint8_t seed[32];
            getRandomSeed(seed);
            PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            const G1Element pk = sk.GetG1Element();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.SignInsecure(message1, sizeof(message1)));
        }

        InsecureG2Element aggSig = InsecureG2Element::Aggregate(sigs);
        const G1Element aggPubKey = G1Element::AggregateInsecure(pks);
        REQUIRE(aggSig.Verify({hash1}, {aggPubKey}));
    }

    SECTION("Should securely aggregate many sigs, same message")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};

        std::vector<PrivateKey> sks;
        std::vector<G1Element> pks;
        std::vector<G2Element> sigs;

        for (int i = 0; i < 70; i++) {
            uint8_t seed[32];
            getRandomSeed(seed);
            PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            const G1Element pk = sk.GetG1Element();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.Sign(message1, sizeof(message1)));
        }

        G2Element aggSig = G2Element::Aggregate(sigs);
        const G1Element aggPubKey = G1Element::Aggregate(pks);
        aggSig.SetAggregationInfo(
            AggregationInfo::FromMsg(aggPubKey, message1, sizeof(message1)));
        REQUIRE(aggSig.Verify());
    }

    SECTION("Should have at least one sig, with AggregationInfo")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));

        std::vector<G2Element> const sigs = {};
        REQUIRE_THROWS(G2Element::Aggregate(sigs));

        sig1.SetAggregationInfo(AggregationInfo());
        std::vector<G2Element> const sigs2 = {sig1};
        REQUIRE_THROWS(G2Element::Aggregate(sigs2));
    }

    SECTION("Should perform batch verification")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[8] = {10, 28, 254, 88, 90, 45, 29, 38};
        uint8_t message3[9] = {10, 28, 254, 88, 90, 45, 29, 38, 177};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);
        uint8_t seed4[32];
        getRandomSeed(seed4);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        G1Element pk2 = sk2.GetG1Element();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        G1Element pk3 = sk3.GetG1Element();

        PrivateKey sk4 = PrivateKey::FromSeed(seed4, 32);
        G1Element pk4 = sk4.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message1, sizeof(message1));
        G2Element sig3 = sk3.Sign(message2, sizeof(message2));
        G2Element sig4 = sk4.Sign(message3, sizeof(message3));
        G2Element sig5 = sk3.Sign(message1, sizeof(message1));
        G2Element sig6 = sk2.Sign(message1, sizeof(message1));
        G2Element sig7 = sk4.Sign(message2, sizeof(message2));

        std::vector<G2Element> const sigs = {
            sig1, sig2, sig3, sig4, sig5, sig6, sig7};
        std::vector<G1Element> const pubKeys = {
            pk1, pk2, pk3, pk4, pk3, pk2, pk4};
        std::vector<uint8_t*> const messages = {message1,
                                                message1,
                                                message2,
                                                message3,
                                                message1,
                                                message1,
                                                message2};
        std::vector<size_t> const messageLens = {sizeof(message1),
                                                 sizeof(message1),
                                                 sizeof(message2),
                                                 sizeof(message3),
                                                 sizeof(message1),
                                                 sizeof(message1),
                                                 sizeof(message2)};

        // Verifier generates a batch G2Element for efficiency
        G2Element aggSig = G2Element::Aggregate(sigs);
        REQUIRE(aggSig.Verify());
    }

    SECTION("Should perform batch verification with cache optimization")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[8] = {10, 28, 254, 88, 90, 45, 29, 38};
        uint8_t message3[9] = {10, 28, 254, 88, 90, 45, 29, 38, 177};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);
        uint8_t seed4[32];
        getRandomSeed(seed4);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        G1Element pk2 = sk2.GetG1Element();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        G1Element pk3 = sk3.GetG1Element();

        PrivateKey sk4 = PrivateKey::FromSeed(seed4, 32);
        G1Element pk4 = sk4.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message1, sizeof(message1));
        G2Element sig3 = sk3.Sign(message2, sizeof(message2));
        G2Element sig4 = sk4.Sign(message3, sizeof(message3));
        G2Element sig5 = sk3.Sign(message1, sizeof(message1));
        G2Element sig6 = sk2.Sign(message1, sizeof(message1));
        G2Element sig7 = sk4.Sign(message2, sizeof(message2));

        std::vector<G2Element> const sigs = {
            sig1, sig2, sig3, sig4, sig5, sig6, sig7};

        REQUIRE(sig1.Verify());
        REQUIRE(sig3.Verify());
        REQUIRE(sig4.Verify());
        REQUIRE(sig7.Verify());
        std::vector<G2Element> cache = {sig1, sig3, sig4, sig7};

        // Verifier generates a batch G2Element for efficiency
        G2Element aggSig = G2Element::Aggregate(sigs);

        const G2Element aggSig2 = aggSig.DivideBy(cache);
        REQUIRE(aggSig.Verify());
        REQUIRE(aggSig2.Verify());
    }

*/
TEST_CASE("Agg sks") {
    SECTION("Should create aggregates with agg sk (basic scheme)")
    {
        const vector<uint8_t> message = {100, 2, 254, 88, 90, 45, 23};
        const vector<uint8_t> seed(32, 0x07);
        const vector<uint8_t> seed2(32, 0x08);

        const PrivateKey sk1 = BasicSchemeMPL::KeyGen(seed);
        const G1Element pk1 = sk1.GetG1Element();

        const PrivateKey sk2 = BasicSchemeMPL::KeyGen(seed2);
        const G1Element pk2 = sk2.GetG1Element();

        const PrivateKey aggSk = PrivateKey::Aggregate({sk1, sk2});
        const PrivateKey aggSkAlt = PrivateKey::Aggregate({sk2, sk1});
        REQUIRE(aggSk == aggSkAlt);

        const G1Element aggPubKey = pk1 + pk2;
        REQUIRE(aggPubKey == aggSk.GetG1Element());

        const G2Element sig1 = BasicSchemeMPL::Sign(sk1, message);
        const G2Element sig2 = BasicSchemeMPL::Sign(sk2, message);

        const G2Element aggSig2 = BasicSchemeMPL::Sign(aggSk, message);


        const G2Element aggSig = BasicSchemeMPL::Aggregate({sig1, sig2});
        REQUIRE(aggSig == aggSig2);

        // Verify as a single G2Element
        REQUIRE(BasicSchemeMPL::Verify(aggPubKey, message, aggSig));
        REQUIRE(BasicSchemeMPL::Verify(aggPubKey, message, aggSig2));

        // Verify aggregate with both keys (Fails since not distinct)
        REQUIRE(BasicSchemeMPL::AggregateVerify({pk1, pk2}, {message, message}, aggSig) == false);
        REQUIRE(BasicSchemeMPL::AggregateVerify({pk1, pk2}, {message, message}, aggSig2) == false);

        // Try the same with distinct message, and same sk
        vector<uint8_t> message2 = {200, 29, 54, 8, 9, 29, 155, 55};
        G2Element sig3 = BasicSchemeMPL::Sign(sk2, message2);
        G2Element aggSigFinal = BasicSchemeMPL::Aggregate({aggSig, sig3});
        G2Element aggSigAlt = BasicSchemeMPL::Aggregate({sig1, sig2, sig3});
        G2Element aggSigAlt2 = BasicSchemeMPL::Aggregate({sig1, sig3, sig2});
        REQUIRE(aggSigFinal == aggSigAlt);
        REQUIRE(aggSigFinal == aggSigAlt2);

        PrivateKey skFinal = PrivateKey::Aggregate({aggSk, sk2});
        PrivateKey skFinalAlt = PrivateKey::Aggregate({sk2, sk1, sk2});
        REQUIRE(skFinal == skFinalAlt);
        REQUIRE(skFinal != aggSk);

        G1Element pkFinal = aggPubKey + pk2;
        G1Element pkFinalAlt = pk2 + pk1 + pk2;
        REQUIRE(pkFinal == pkFinalAlt);
        REQUIRE(pkFinal != aggPubKey);

        // Cannot verify with aggPubKey (since we have multiple messages)
        REQUIRE(BasicSchemeMPL::AggregateVerify({aggPubKey, pk2}, {message, message2}, aggSigFinal));
    }
}


/*
    SECTION("Should aggregate with multiple levels.")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[8] = {192, 29, 2, 0, 0, 45, 23, 192};
        uint8_t message3[7] = {52, 29, 2, 0, 0, 45, 102};
        uint8_t message4[7] = {99, 29, 2, 0, 0, 45, 222};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);

        G1Element pk1 = sk1.GetG1Element();
        G1Element pk2 = sk2.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message2, sizeof(message2));
        G2Element sig3 = sk2.Sign(message1, sizeof(message1));
        G2Element sig4 = sk1.Sign(message3, sizeof(message3));
        G2Element sig5 = sk1.Sign(message4, sizeof(message4));
        G2Element sig6 = sk1.Sign(message1, sizeof(message1));

        std::vector<G2Element> const sigsL = {sig1, sig2};
        std::vector<G1Element> const pksL = {pk1, pk2};
        const G2Element aggSigL = G2Element::Aggregate(sigsL);

        std::vector<G2Element> const sigsR = {sig3, sig4, sig6};
        const G2Element aggSigR = G2Element::Aggregate(sigsR);

        std::vector<G1Element> pk1Vec = {pk1};

        std::vector<G2Element> sigs = {aggSigL, aggSigR, sig5};

        const G2Element aggSig = G2Element::Aggregate(sigs);

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should aggregate with multiple levels, degenerate")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();
        G2Element aggSig = sk1.Sign(message1, sizeof(message1));

        for (size_t i = 0; i < 10; i++) {
            getRandomSeed(seed);
            PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            G1Element pk = sk.GetG1Element();
            G2Element sig = sk.Sign(message1, sizeof(message1));
            std::vector<G2Element> sigs = {aggSig, sig};
            aggSig = G2Element::Aggregate(sigs);
        }
        REQUIRE(aggSig.Verify());
        uint8_t sigSerialized[G2Element::G2Element_SIZE];
        aggSig.Serialize(sigSerialized);

        const G2Element aggSig2 = G2Element::FromBytes(sigSerialized);
        REQUIRE(aggSig2.Verify() == false);
    }

    SECTION("Should aggregate with multiple levels, different messages")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[7] = {192, 29, 2, 0, 0, 45, 23};
        uint8_t message3[7] = {52, 29, 2, 0, 0, 45, 102};
        uint8_t message4[7] = {99, 29, 2, 0, 0, 45, 222};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);

        G1Element pk1 = sk1.GetG1Element();
        G1Element pk2 = sk2.GetG1Element();

        G2Element sig1 = sk1.Sign(message1, sizeof(message1));
        G2Element sig2 = sk2.Sign(message2, sizeof(message2));
        G2Element sig3 = sk2.Sign(message3, sizeof(message4));
        G2Element sig4 = sk1.Sign(message4, sizeof(message4));

        std::vector<G2Element> const sigsL = {sig1, sig2};
        std::vector<G1Element> const pksL = {pk1, pk2};
        std::vector<uint8_t*> const messagesL = {message1, message2};
        std::vector<size_t> const messageLensL = {sizeof(message1),
                                                  sizeof(message2)};
        const G2Element aggSigL = G2Element::Aggregate(sigsL);

        std::vector<G2Element> const sigsR = {sig3, sig4};
        std::vector<G1Element> const pksR = {pk2, pk1};
        std::vector<uint8_t*> const messagesR = {message3, message4};
        std::vector<size_t> const messageLensR = {sizeof(message3),
                                                  sizeof(message4)};
        const G2Element aggSigR = G2Element::Aggregate(sigsR);

        std::vector<G2Element> sigs = {aggSigL, aggSigR};
        std::vector<std::vector<G1Element>> pks = {pksL, pksR};
        std::vector<std::vector<uint8_t*>> messages = {messagesL, messagesR};
        std::vector<std::vector<size_t>> messageLens = {messageLensL,
                                                        messageLensR};

        const G2Element aggSig = G2Element::Aggregate(sigs);

        std::vector<G1Element> allPks = {pk1, pk2, pk2, pk1};
        std::vector<uint8_t*> allMessages = {
            message1, message2, message3, message4};
        std::vector<size_t> allMessageLens = {sizeof(message1),
                                              sizeof(message2),
                                              sizeof(message3),
                                              sizeof(message4)};

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should sign and verify using prepend method")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        G1Element pk1 = sk1.GetG1Element();
        std::cout << "PK: " << pk1 << std::endl;

        uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash, message1, 7);
        vector<const uint8_t*> messageHashes = {messageHash};
        vector<G1Element> pks = {pk1};

        const PrependG2Element sig1 = sk1.SignPrepend(message1, 7);
        REQUIRE(sig1.Verify(messageHashes, pks));

        uint8_t sigData[PrependG2Element::G2Element_SIZE];
        uint8_t sigData2[PrependG2Element::G2Element_SIZE];
        sig1.Serialize(sigData);
        sig1.GetInsecureSig().Serialize(sigData2);
        REQUIRE(
            memcmp(sigData, sigData2, PrependG2Element::G2Element_SIZE) != 0);

        PrependG2Element sig2 = PrependG2Element::FromBytes(sigData);
        REQUIRE(sig1 == sig2);

        REQUIRE(sig2.Verify(messageHashes, pks));
    }

    SECTION("Should aggregate using prepend method")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[7] = {192, 29, 2, 0, 0, 45, 23};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);

        G1Element pk1 = sk1.GetG1Element();
        G1Element pk2 = sk2.GetG1Element();
        G1Element pk3 = sk3.GetG1Element();

        PrependG2Element sig1 = sk1.SignPrepend(message1, 7);
        PrependG2Element sig2 = sk2.SignPrepend(message1, 7);
        PrependG2Element sig3 = sk3.SignPrepend(message2, 7);

        uint8_t messageHash1[BLS::MESSAGE_HASH_LEN];
        uint8_t messageHash2[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash1, message1, 7);
        Util::Hash256(messageHash2, message2, 7);
        vector<const uint8_t*> messageHashes1 = {messageHash1};
        vector<const uint8_t*> messageHashes2 = {messageHash2};
        vector<const uint8_t*> messageHashes = {
            messageHash1, messageHash1, messageHash2};
        vector<G1Element> pks1 = {pk1};
        vector<G1Element> pks2 = {pk2};
        vector<G1Element> pks3 = {pk3};
        vector<G1Element> pks = {pk1, pk2, pk3};

        REQUIRE(sig1.Verify(messageHashes1, pks1));
        REQUIRE(sig2.Verify(messageHashes1, pks2));
        REQUIRE(sig3.Verify(messageHashes2, pks3));

        vector<PrependG2Element> sigs = {sig1, sig2, sig3};

        PrependG2Element agg = PrependG2Element::Aggregate(sigs);
        REQUIRE(agg.Verify(messageHashes, pks));

        vector<G1Element> pksWrong = {pk1, pk2, pk2};
        REQUIRE(agg.Verify(messageHashes, pksWrong) == false);
    }

    SECTION("README")
    {
        // Example seed, used to generate private key. Always use
        // a secure RNG with sufficient entropy to generate a seed.
        uint8_t seed[] = {0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                          19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                          12, 62, 89, 110, 182, 9,   44, 20,  254, 22};

        PrivateKey sk = PrivateKey::FromSeed(seed, sizeof(seed));
        G1Element pk = sk.GetG1Element();

        uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};

        G2Element sig = sk.Sign(msg, sizeof(msg));

        uint8_t skBytes[PrivateKey::PRIVATE_KEY_SIZE];  // 32 byte array
        uint8_t pkBytes[G1Element::PUBLIC_KEY_SIZE];    // 48 byte array
        uint8_t sigBytes[G2Element::G2Element_SIZE];    // 96 byte array

        sk.Serialize(skBytes);    // 32 bytes
        pk.Serialize(pkBytes);    // 48 bytes
        sig.Serialize(sigBytes);  // 96 bytes
        // Takes array of 32 bytes
        sk = PrivateKey::FromBytes(skBytes);

        // Takes array of 48 bytes
        pk = G1Element::FromBytes(pkBytes);

        // Takes array of 96 bytes
        sig = G2Element::FromBytes(sigBytes);
        // Add information required for verification, to sig object
        sig.SetAggregationInfo(AggregationInfo::FromMsg(pk, msg, sizeof(msg)));

        bool ok = sig.Verify();
        // Generate some more private keys
        seed[0] = 1;
        PrivateKey sk1 = PrivateKey::FromSeed(seed, sizeof(seed));
        seed[0] = 2;
        PrivateKey sk2 = PrivateKey::FromSeed(seed, sizeof(seed));

        // Generate first sig
        G1Element pk1 = sk1.GetG1Element();
        G2Element sig1 = sk1.Sign(msg, sizeof(msg));

        // Generate second sig
        G1Element pk2 = sk2.GetG1Element();
        G2Element sig2 = sk2.Sign(msg, sizeof(msg));

        // Aggregate G2Elements together
        std::vector<G2Element> sigs = {sig1, sig2};
        G2Element aggSig = G2Element::Aggregate(sigs);

        // For same message, public keys can be aggregated into one.
        // The G2Element can be verified the same as a single G2Element,
        // using this public key.
        std::vector<G1Element> pubKeys = {pk1, pk2};
        G1Element aggPubKey = G1Element::Aggregate(pubKeys);
        // Generate one more key
        seed[0] = 3;
        PrivateKey sk3 = PrivateKey::FromSeed(seed, sizeof(seed));
        G1Element pk3 = sk3.GetG1Element();
        uint8_t msg2[] = {100, 2, 254, 88, 90, 45, 23};

        // Generate the G2Elements, assuming we have 3 private keys
        sig1 = sk1.Sign(msg, sizeof(msg));
        sig2 = sk2.Sign(msg, sizeof(msg));
        G2Element sig3 = sk3.Sign(msg2, sizeof(msg2));

        // They can be noninteractively combined by anyone
        // Aggregation below can also be done by the verifier, to
        // make batch verification more efficient
        std::vector<G2Element> sigsL = {sig1, sig2};
        G2Element aggSigL = G2Element::Aggregate(sigsL);

        // Arbitrary trees of aggregates
        std::vector<G2Element> sigsFinal = {aggSigL, sig3};
        G2Element aggSigFinal = G2Element::Aggregate(sigsFinal);

        // Serialize the final G2Element
        aggSigFinal.Serialize(sigBytes);
        // Deserialize aggregate G2Element
        aggSigFinal = G2Element::FromBytes(sigBytes);

        // Create aggregation information (or deserialize it)
        AggregationInfo a1 = AggregationInfo::FromMsg(pk1, msg, sizeof(msg));
        AggregationInfo a2 = AggregationInfo::FromMsg(pk2, msg, sizeof(msg));
        AggregationInfo a3 = AggregationInfo::FromMsg(pk3, msg2, sizeof(msg2));
        std::vector<AggregationInfo> infos = {a1, a2};
        AggregationInfo a1a2 = AggregationInfo::MergeInfos(infos);
        std::vector<AggregationInfo> infos2 = {a1a2, a3};
        AggregationInfo aFinal = AggregationInfo::MergeInfos(infos2);

        // Verify final G2Element using the aggregation info
        aggSigFinal.SetAggregationInfo(aFinal);
        ok = aggSigFinal.Verify();

        // If you previously verified a G2Element, you can also divide
        // the aggregate G2Element by the G2Element you already verified.
        ok = aggSigL.Verify();
        std::vector<G2Element> cache = {aggSigL};
        aggSigFinal = aggSigFinal.DivideBy(cache);

        // Final verification is now more efficient
        ok = aggSigFinal.Verify();

        std::vector<PrivateKey> privateKeysList = {sk1, sk2};
        std::vector<G1Element> pubKeysList = {pk1, pk2};

        // Create an aggregate private key, that can generate
        // aggregate G2Elements
        const PrivateKey aggSk =
            PrivateKey::Aggregate(privateKeysList, pubKeysList);

        G2Element aggSig3 = aggSk.Sign(msg, sizeof(msg));

        PrependG2Element prepend1 = sk1.SignPrepend(msg, sizeof(msg));
        PrependG2Element prepend2 = sk2.SignPrepend(msg, sizeof(msg));
        std::vector<G1Element> prependPubKeys = {pk1, pk2};
        uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash, msg, sizeof(msg));
        std::vector<const uint8_t*> hashes = {messageHash, messageHash};
        std::vector<PrependG2Element> prependSigs = {prepend1, prepend2};
        PrependG2Element prependAgg = PrependG2Element::Aggregate(prependSigs);
        prependAgg.Verify(hashes, prependPubKeys);
    }
}

TEST_CASE("Threshold")
{
    SECTION("Threshold tests")
    {
        // To initialize a T of N threshold key under a
        // Joint-Feldman scheme:
        size_t T = 2;
        size_t N = 3;

        // 1. Each player calls Threshold::Create.
        // They send everyone commitment to the polynomial,
        // and send secret share fragments frags[j-1] to
        // the j-th player (All players have index >= 1).

        // G1Element commits[N][T]
        // PrivateKey frags[N][N]
        std::vector<std::vector<G1Element>> commits;
        std::vector<std::vector<PrivateKey>> frags;
        for (size_t i = 0; i < N; ++i) {
            commits.emplace_back(std::vector<G1Element>());
            frags.emplace_back(std::vector<PrivateKey>());
            for (size_t j = 0; j < N; ++j) {
                if (j < T) {
                    g1_t g;
                    commits[i].emplace_back(G1Element::FromG1(&g));
                }
                bn_t b;
                bn_new(b);
                frags[i].emplace_back(PrivateKey::FromBN(b));
            }
        }

        PrivateKey sk1 = Threshold::Create(commits[0], frags[0], T, N);
        PrivateKey sk2 = Threshold::Create(commits[1], frags[1], T, N);
        PrivateKey sk3 = Threshold::Create(commits[2], frags[2], T, N);

        // 2. Each player calls Threshold::VerifySecretFragment
        // on all secret fragments they receive.  If any verify
        // false, they complain to abort the scheme.  (Note that
        // repeatedly aborting, or 'speaking' last, can bias the
        // master public key.)

        for (int target = 1; target <= N; ++target) {
            for (int source = 1; source <= N; ++source) {
                REQUIRE(Threshold::VerifySecretFragment(
                    target,
                    frags[source - 1][target - 1],
                    commits[source - 1],
                    T));
            }
        }

        // 3. Each player computes the shared, master public key:
        // masterPubkey = G1Element::AggregateInsecure(...)
        // They also create their secret share from all secret
        // fragments received (now verified):
        // secretShare = PrivateKey::AggregateInsecure(...)

        G1Element masterPubkey = G1Element::AggregateInsecure(
            {commits[0][0], commits[1][0], commits[2][0]});

        // recvdFrags[j][i] = frags[i][j]
        std::vector<std::vector<PrivateKey>> recvdFrags = {{}};
        for (int i = 0; i < N; ++i) {
            recvdFrags.emplace_back(std::vector<PrivateKey>());
            for (int j = 0; j < N; ++j) {
                recvdFrags[i].emplace_back(frags[j][i]);
            }
        }

        PrivateKey secretShare1 = PrivateKey::AggregateInsecure(recvdFrags[0]);
        PrivateKey secretShare2 = PrivateKey::AggregateInsecure(recvdFrags[1]);
        PrivateKey secretShare3 = PrivateKey::AggregateInsecure(recvdFrags[2]);

        // 4a. Player P creates a pre-multiplied G2Element share wrt T players:
        // sigShare = Threshold::SignWithCoefficient(...)
        // These G2Element shares can be combined to sign the msg:
        // G2Element = InsecureG2Element::Aggregate(...)
        // The advantage of this approach is that forming the final G2Element
        // no longer requires information about the players.

        uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t hash[32];
        Util::Hash256(hash, msg, sizeof(msg));

        size_t players[] = {1, 3};
        // For example, players 1 and 3 sign.
        // As we have verified the coefficients through the commitments given,
        // using InsecureG2Element is okay.
        InsecureG2Element sigShareC1 = Threshold::SignWithCoefficient(
            secretShare1, msg, (size_t)sizeof(msg), (size_t)1, players, T);
        InsecureG2Element sigShareC3 = Threshold::SignWithCoefficient(
            secretShare3, msg, (size_t)sizeof(msg), (size_t)3, players, T);

        InsecureG2Element G2Element =
            InsecureG2Element::Aggregate({sigShareC1, sigShareC3});

        REQUIRE(G2Element.Verify({hash}, {masterPubkey}));

        // 4b. Alternatively, players may sign the message blindly, creating
        // a unit G2Element share: sigShare = secretShare.SignInsecure(...)
        // These G2Elements may be combined with lagrange coefficients to
        // sign the message: G2Element = Threshold::AggregateUnitSigs(...)
        // The advantage to this approach is that each player does not need
        // to know the final list of signatories.

        // For example, players 1 and 3 sign.
        InsecureG2Element sigShareU1 =
            secretShare1.SignInsecure(msg, (size_t)sizeof(msg));
        InsecureG2Element sigShareU3 =
            secretShare3.SignInsecure(msg, (size_t)sizeof(msg));
        InsecureG2Element G2Element2 = Threshold::AggregateUnitSigs(
            {sigShareU1, sigShareU3}, msg, (size_t)sizeof(msg), players, T);

        REQUIRE(G2Element2.Verify({hash}, {masterPubkey}));
    }
}
*/

TEST_CASE("Schemes")
{
    /*
    SECTION("Debug")
    {
        vector<uint8_t> msg0 = {};
        vector<uint8_t> msg1 = {1, 2, 3};
        uint8_t seed1[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
        PrivateKey sk1 = PrivateKey::FromBytes(seed1, true);
        vector<uint8_t> sk1ser = sk1.Serialize();
        std::stringstream ss;
        ss << std::hex;

        for (int i = 0; i < 32; ++i)
            ss << std::setw(2) << std::setfill('0') << (int)sk1ser[i];

        std::cout << "sk1: " << ss.str() << "\n";
        G1Element pk1 = BasicSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = BasicSchemeMPL::SkToPk(sk1);
        G2Element sig1 = BasicSchemeMPL::Sign(sk1, msg1);
        vector<uint8_t> sig1v = BasicSchemeMPL::Sign(sk1, msg1);
        std::cout << "PK1: " << pk1 << "\n";
        std::cout << "SIG1: " << sig1 << "\n";
        G2Element sig0 = BasicSchemeMPL::Sign(sk1, msg0);
        std::cout << "SIG0: " << sig0 << "\n";
    }
    */

    SECTION("Basic Scheme")
    {
        vector<uint8_t> seed1(32, 0x04);
        vector<uint8_t> seed2(32, 0x05);
        vector<uint8_t> msg1 = {7, 8, 9};
        vector<uint8_t> msg2 = {10, 11, 12};
        vector<vector<uint8_t>> msgs = {msg1, msg2};

        PrivateKey sk1 = BasicSchemeMPL::KeyGen(seed1);
        G1Element pk1 = BasicSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = BasicSchemeMPL::SkToPk(sk1);
        G2Element sig1 = BasicSchemeMPL::Sign(sk1, msg1);
        vector<uint8_t> sig1v = BasicSchemeMPL::Sign(sk1, msg1).Serialize();


        REQUIRE(BasicSchemeMPL::Verify(pk1v, msg1, sig1v));

        PrivateKey sk2 = BasicSchemeMPL::KeyGen(seed2);
        G1Element pk2 = BasicSchemeMPL::SkToG1(sk2);
        vector<uint8_t> pk2v = BasicSchemeMPL::SkToPk(sk2);
        G2Element sig2 = BasicSchemeMPL::Sign(sk2, msg2);
        vector<uint8_t> sig2v = BasicSchemeMPL::Sign(sk2, msg2).Serialize();

        // Wrong G2Element
        REQUIRE(BasicSchemeMPL::Verify(pk1, msg1, sig2) == false);
        REQUIRE(BasicSchemeMPL::Verify(pk1v, msg1, sig2v) == false);
        // Wrong msg
        REQUIRE(BasicSchemeMPL::Verify(pk1, msg2, sig1) == false);
        REQUIRE(BasicSchemeMPL::Verify(pk1v, msg2, sig1v) == false);
        // Wrong pk
        REQUIRE(BasicSchemeMPL::Verify(pk2, msg1, sig1) == false);
        REQUIRE(BasicSchemeMPL::Verify(pk2v, msg1, sig1v) == false);

        G2Element aggsig = BasicSchemeMPL::Aggregate({sig1, sig2});
        vector<uint8_t> aggsigv = BasicSchemeMPL::Aggregate({sig1v, sig2v});
        REQUIRE(BasicSchemeMPL::AggregateVerify({pk1, pk2}, msgs, aggsig));
        REQUIRE(BasicSchemeMPL::AggregateVerify({pk1v, pk2v}, msgs, aggsigv));
    }

    SECTION("Aug Scheme")
    {
        vector<uint8_t> seed1(32, 0x04);
        vector<uint8_t> seed2(32, 0x05);
        vector<uint8_t> msg1 = {7, 8, 9};
        vector<uint8_t> msg2 = {10, 11, 12};
        vector<vector<uint8_t>> msgs = {msg1, msg2};

        PrivateKey sk1 = AugSchemeMPL::KeyGen(seed1);
        G1Element pk1 = AugSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = AugSchemeMPL::SkToPk(sk1);
        G2Element sig1 = AugSchemeMPL::Sign(sk1, msg1);
        vector<uint8_t> sig1v = AugSchemeMPL::Sign(sk1, msg1).Serialize();

        REQUIRE(AugSchemeMPL::Verify(pk1, msg1, sig1));
        REQUIRE(AugSchemeMPL::Verify(pk1v, msg1, sig1v));

        PrivateKey sk2 = AugSchemeMPL::KeyGen(seed2);
        G1Element pk2 = AugSchemeMPL::SkToG1(sk2);
        vector<uint8_t> pk2v = AugSchemeMPL::SkToPk(sk2);
        G2Element sig2 = AugSchemeMPL::Sign(sk2, msg2);
        vector<uint8_t> sig2v = AugSchemeMPL::Sign(sk2, msg2).Serialize();

        // Wrong G2Element
        REQUIRE(AugSchemeMPL::Verify(pk1, msg1, sig2) == false);
        REQUIRE(AugSchemeMPL::Verify(pk1v, msg1, sig2v) == false);
        // Wrong msg
        REQUIRE(AugSchemeMPL::Verify(pk1, msg2, sig1) == false);
        REQUIRE(AugSchemeMPL::Verify(pk1v, msg2, sig1v) == false);
        // Wrong pk
        REQUIRE(AugSchemeMPL::Verify(pk2, msg1, sig1) == false);
        REQUIRE(AugSchemeMPL::Verify(pk2v, msg1, sig1v) == false);

        G2Element aggsig = AugSchemeMPL::Aggregate({sig1, sig2});
        vector<uint8_t> aggsigv = AugSchemeMPL::Aggregate({sig1v, sig2v});
        REQUIRE(AugSchemeMPL::AggregateVerify({pk1, pk2}, msgs, aggsig));
        REQUIRE(AugSchemeMPL::AggregateVerify({pk1v, pk2v}, msgs, aggsigv));
    }

    SECTION("Pop Scheme")
    {
        vector<uint8_t> seed1(32, 0x06);
        vector<uint8_t> seed2(32, 0x07);
        vector<uint8_t> msg1 = {7, 8, 9};
        vector<uint8_t> msg2 = {10, 11, 12};
        vector<vector<uint8_t>> msgs = {msg1, msg2};

        PrivateKey sk1 = PopSchemeMPL::KeyGen(seed1);
        G1Element pk1 = PopSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = PopSchemeMPL::SkToPk(sk1);
        G2Element sig1 = PopSchemeMPL::Sign(sk1, msg1);
        vector<uint8_t> sig1v = PopSchemeMPL::Sign(sk1, msg1).Serialize();

        REQUIRE(PopSchemeMPL::Verify(pk1, msg1, sig1));
        REQUIRE(PopSchemeMPL::Verify(pk1v, msg1, sig1v));

        PrivateKey sk2 = PopSchemeMPL::KeyGen(seed2);
        G1Element pk2 = PopSchemeMPL::SkToG1(sk2);
        vector<uint8_t> pk2v = PopSchemeMPL::SkToPk(sk2);
        G2Element sig2 = PopSchemeMPL::Sign(sk2, msg2);
        vector<uint8_t> sig2v = PopSchemeMPL::Sign(sk2, msg2).Serialize();

        // Wrong G2Element
        REQUIRE(PopSchemeMPL::Verify(pk1, msg1, sig2) == false);
        REQUIRE(PopSchemeMPL::Verify(pk1v, msg1, sig2v) == false);
        // Wrong msg
        REQUIRE(PopSchemeMPL::Verify(pk1, msg2, sig1) == false);
        REQUIRE(PopSchemeMPL::Verify(pk1v, msg2, sig1v) == false);
        // Wrong pk
        REQUIRE(PopSchemeMPL::Verify(pk2, msg1, sig1) == false);
        REQUIRE(PopSchemeMPL::Verify(pk2v, msg1, sig1v) == false);

        G2Element aggsig = PopSchemeMPL::Aggregate({sig1, sig2});
        vector<uint8_t> aggsigv = PopSchemeMPL::Aggregate({sig1v, sig2v});
        REQUIRE(PopSchemeMPL::AggregateVerify({pk1, pk2}, msgs, aggsig));
        REQUIRE(PopSchemeMPL::AggregateVerify({pk1v, pk2v}, msgs, aggsigv));

        // PopVerify
        G2Element proof1 = PopSchemeMPL::PopProveNative(sk1);
        vector<uint8_t> proof1v = PopSchemeMPL::PopProve(sk1);
        REQUIRE(PopSchemeMPL::PopVerify(pk1, proof1));
        REQUIRE(PopSchemeMPL::PopVerify(pk1v, proof1v));

        // FastAggregateVerify
        // We want sk2 to sign the same message
        G2Element sig2_same = PopSchemeMPL::Sign(sk2, msg1);
        vector<uint8_t> sig2v_same = PopSchemeMPL::Sign(sk2, msg1).Serialize();
        G2Element aggsig_same = PopSchemeMPL::Aggregate({sig1, sig2_same});
        vector<uint8_t> aggsigv_same =
            PopSchemeMPL::Aggregate({sig1v, sig2v_same});
        REQUIRE(
            PopSchemeMPL::FastAggregateVerify({pk1, pk2}, msg1, aggsig_same));
        REQUIRE(PopSchemeMPL::FastAggregateVerify(
            {pk1v, pk2v}, msg1, aggsigv_same));
    }
}

int main(int argc, char* argv[])
{
    int result = Catch::Session().run(argc, argv);
    return result;
}
