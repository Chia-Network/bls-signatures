
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
    auto seed = Util::HexToBytes(seedHex);
    auto masterSk = Util::HexToBytes(masterSkHex);
    auto childSk = Util::HexToBytes(childSkHex);

    PrivateKey master = PrivateKey::FromSeed(seed.data(), seed.size());
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

TEST_CASE("EIP-2333 HD keys") {
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

/*
TEST_CASE("Test vectors")
{
    SECTION("Test vectors 1")
    {
        uint8_t seed1[5] = {1, 2, 3, 4, 5};
        uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};
        uint8_t message1[3] = {7, 8, 9};

        PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
        PublicKey pk1 = sk1.GetPublicKey();
        Signature sig1 = sk1.Sign(message1, sizeof(message1));

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));
        PublicKey pk2 = sk2.GetPublicKey();
        Signature sig2 = sk2.Sign(message1, sizeof(message1));

        uint8_t buf[Signature::SIGNATURE_SIZE];
        uint8_t buf2[PrivateKey::PRIVATE_KEY_SIZE];

        REQUIRE(pk1.GetFingerprint() == 0x26d53247);
        REQUIRE(pk2.GetFingerprint() == 0x289bb56e);

        sig1.Serialize(buf);
        sk1.Serialize(buf2);

        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "93eb2e1cb5efcfb31f2c08b235e8203a67265bc6a13d9f0ab77727293b74a357ff"
            "0459ac210dc851fcb8a60cb7d393a419915cfcf83908ddbeac32039aaa3e8fea82"
            "efcb3ba4f740f20c76df5e97109b57370ae32d9b70d256a98942e5806065");
        REQUIRE(
            Util::HexStr(buf2, PrivateKey::PRIVATE_KEY_SIZE) ==
            "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e");

        sig2.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "975b5daa64b915be19b5ac6d47bc1c2fc832d2fb8ca3e95c4805d8216f95cf2bdb"
            "b36cc23645f52040e381550727db420b523b57d494959e0e8c0c6060c46cf17387"
            "2897f14d43b2ac2aec52fc7b46c02c5699ff7a10beba24d3ced4e89c821e");

        vector<Signature> sigs = {sig1, sig2};
        Signature aggSig1 = Signature::Aggregate(sigs);

        aggSig1.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "0a638495c1403b25be391ed44c0ab013390026b5892c796a85ede46310ff7d0e06"
            "71f86ebe0e8f56bee80f28eb6d999c0a418c5fc52debac8fc338784cd32b76338d"
            "629dc2b4045a5833a357809795ef55ee3e9bee532edfc1d9c443bf5bc658");
        REQUIRE(aggSig1.Verify());

        uint8_t message2[3] = {1, 2, 3};
        uint8_t message3[4] = {1, 2, 3, 4};
        uint8_t message4[2] = {1, 2};
        Signature sig3 = sk1.Sign(message2, sizeof(message2));
        Signature sig4 = sk1.Sign(message3, sizeof(message3));
        Signature sig5 = sk2.Sign(message4, sizeof(message4));
        vector<Signature> sigs2 = {sig3, sig4, sig5};
        Signature aggSig2 = Signature::Aggregate(sigs2);
        REQUIRE(aggSig2.Verify());
        aggSig2.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "8b11daf73cd05f2fe27809b74a7b4c65b1bb79cc1066bdf839d96b97e073c1a635"
            "d2ec048e0801b4a208118fdbbb63a516bab8755cc8d850862eeaa099540cd83621"
            "ff9db97b4ada857ef54c50715486217bd2ecb4517e05ab49380c041e159b");
    }

    SECTION("Test vector 2")
    {
        uint8_t message1[4] = {1, 2, 3, 40};
        uint8_t message2[4] = {5, 6, 70, 201};
        uint8_t message3[5] = {9, 10, 11, 12, 13};
        uint8_t message4[6] = {15, 63, 244, 92, 0, 1};

        uint8_t seed1[5] = {1, 2, 3, 4, 5};
        uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};

        PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
        PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message2, sizeof(message2));
        Signature sig3 = sk2.Sign(message1, sizeof(message1));
        Signature sig4 = sk1.Sign(message3, sizeof(message3));
        Signature sig5 = sk1.Sign(message1, sizeof(message1));
        Signature sig6 = sk1.Sign(message4, sizeof(message4));

        std::vector<Signature> const sigsL = {sig1, sig2};
        const Signature aggSigL = Signature::Aggregate(sigsL);

        std::vector<Signature> const sigsR = {sig3, sig4, sig5};
        const Signature aggSigR = Signature::Aggregate(sigsR);

        std::vector<Signature> sigs = {aggSigL, aggSigR, sig6};

        Signature aggSig = Signature::Aggregate(sigs);

        REQUIRE(aggSig.Verify());

        uint8_t buf[Signature::SIGNATURE_SIZE];
        aggSig.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "07969958fbf82e65bd13ba0749990764cac81cf10d923af9fdd2723f1e3910c3fd"
            "b874a67f9d511bb7e4920f8c01232b12e2fb5e64a7c2d177a475dab5c3729ca1f5"
            "80301ccdef809c57a8846890265d195b694fa414a2a3aa55c32837fddd80");
        vector<Signature> signatures_to_divide = {sig2, sig5, sig6};
        Signature quotient = aggSig.DivideBy(signatures_to_divide);
        aggSig.DivideBy(signatures_to_divide);

        quotient.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "8ebc8a73a2291e689ce51769ff87e517be6089fd0627b2ce3cd2f0ee1ce134b39c"
            "4da40928954175014e9bbe623d845d0bdba8bfd2a85af9507ddf145579480132b6"
            "76f027381314d983a63842fcc7bf5c8c088461e3ebb04dcf86b431d6238f");

        REQUIRE(quotient.Verify());
        REQUIRE(quotient.DivideBy(vector<Signature>()) == quotient);
        signatures_to_divide = {sig6};
        REQUIRE_THROWS(quotient.DivideBy(signatures_to_divide));

        // Should not throw
        signatures_to_divide = {sig1};
        aggSig.DivideBy(signatures_to_divide);

        // Should throw due to not unique
        signatures_to_divide = {aggSigL};
        REQUIRE_THROWS(aggSig.DivideBy(signatures_to_divide));

        Signature sig7 = sk2.Sign(message3, sizeof(message3));
        Signature sig8 = sk2.Sign(message4, sizeof(message4));

        // Divide by aggregate
        std::vector<Signature> sigsR2 = {sig7, sig8};
        Signature aggSigR2 = Signature::Aggregate(sigsR2);
        std::vector<Signature> sigsFinal2 = {aggSig, aggSigR2};
        Signature aggSig2 = Signature::Aggregate(sigsFinal2);
        std::vector<Signature> divisorFinal2 = {aggSigR2};
        Signature quotient2 = aggSig2.DivideBy(divisorFinal2);

        REQUIRE(quotient2.Verify());
        quotient2.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "06af6930bd06838f2e4b00b62911fb290245cce503ccf5bfc2901459897731dd08"
            "fc4c56dbde75a11677ccfbfa61ab8b14735fddc66a02b7aeebb54ab9a41488f89f"
            "641d83d4515c4dd20dfcf28cbbccb1472c327f0780be3a90c005c58a47d3");
    }

    SECTION("Test vector 3")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        REQUIRE(esk.GetPublicKey().GetFingerprint() == 0xa4700b27);
        uint8_t chainCode[32];
        esk.GetChainCode().Serialize(chainCode);
        REQUIRE(
            Util::HexStr(chainCode, 32) ==
            "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3");

        ExtendedPrivateKey esk77 = esk.PrivateChild(77 + (1 << 31));
        esk77.GetChainCode().Serialize(chainCode);
        REQUIRE(
            Util::HexStr(chainCode, 32) ==
            "f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b");
        REQUIRE(
            esk77.GetPrivateKey().GetPublicKey().GetFingerprint() ==
            0xa8063dcf);

        REQUIRE(
            esk.PrivateChild(3)
                .PrivateChild(17)
                .GetPublicKey()
                .GetFingerprint() == 0xff26a31f);
        REQUIRE(
            esk.GetExtendedPublicKey()
                .PublicChild(3)
                .PublicChild(17)
                .GetPublicKey()
                .GetFingerprint() == 0xff26a31f);
    }

    SECTION("Test vector 4")
    {
        uint8_t seed1[5] = {1, 2, 3, 4, 5};
        uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};
        uint8_t message1[3] = {7, 8, 9};
        uint8_t message2[3] = {10, 11, 12};

        PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));
        PublicKey pk2 = sk2.GetPublicKey();

        PrependSignature sig9 = sk1.SignPrepend(message1, sizeof(message1));
        PrependSignature sig10 = sk2.SignPrepend(message2, sizeof(message2));

        uint8_t buf[Signature::SIGNATURE_SIZE];
        sig9.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "d2135ad358405d9f2d4e68dc253d64b6049a821797817cffa5aa804086a8fb7b13"
            "5175bb7183750e3aa19513db1552180f0b0ffd513c322f1c0c30a0a9c179f6e275"
            "e0109d4db7fa3e09694190947b17d890f3d58fe0b1866ec4d4f5a59b16ed");
        sig10.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "cc58c982f9ee5817d4fbf22d529cfc6792b0fdcf2d2a8001686755868e10eb32b4"
            "0e464e7fbfe30175a962f1972026f2087f0495ba6e293ac3cf271762cd6979b941"
            "3adc0ba7df153cf1f3faab6b893404c2e6d63351e48cd54e06e449965f08");

        uint8_t messageHash1[BLS::MESSAGE_HASH_LEN];
        uint8_t messageHash2[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash1, message1, sizeof(message1));
        Util::Hash256(messageHash2, message2, sizeof(message2));
        vector<const uint8_t*> messageHashes1 = {messageHash1};
        vector<const uint8_t*> messageHashes2 = {messageHash2};
        vector<const uint8_t*> messageHashes = {
            messageHash1, messageHash1, messageHash2};
        vector<PublicKey> pks = {pk1, pk1, pk2};

        vector<PrependSignature> sigs = {sig9, sig9, sig10};
        PrependSignature agg = PrependSignature::Aggregate(sigs);

        agg.Serialize(buf);
        REQUIRE(
            Util::HexStr(buf, Signature::SIGNATURE_SIZE) ==
            "c37077684e735e62e3f1fd17772a236b4115d4b581387733d3b97cab08b90918c7"
            "e91c23380c93e54be345544026f93505d41e6000392b82ab3c8af1b2e3954b0ef3"
            "f62c52fc89f99e646ff546881120396c449856428e672178e5e0e14ec894");

        REQUIRE(agg.Verify(messageHashes, pks));
    }
}

TEST_CASE("Key generation")
{
    SECTION("Should generate a keypair from a seed")
    {
        uint8_t seed[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

        PrivateKey sk = PrivateKey::FromSeed(seed, sizeof(seed));
        PublicKey pk = sk.GetPublicKey();
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
        uint8_t* skData = Util::SecAlloc<uint8_t>(Signature::SIGNATURE_SIZE);
        sk1.Serialize(skData);
        skData[0] = 255;
        REQUIRE_THROWS(PrivateKey::FromBytes(skData));

        Util::SecFree(skData);
    }

    SECTION("Should throw on a bad public key")
    {
        uint8_t buf[PublicKey::PUBLIC_KEY_SIZE] = {0};
        std::set<int> invalid = {1, 2, 3, 4};

        for (int i = 0; i < 10; i++) {
            buf[0] = (uint8_t)i;
            try {
                PublicKey::FromBytes(buf);
                REQUIRE(invalid.count(i) == 0);
            } catch (std::invalid_argument& s) {
                REQUIRE(invalid.count(i) != 0);
            }
        }
    }

    SECTION("Should throw on a bad signature")
    {
        uint8_t buf[Signature::SIGNATURE_SIZE] = {0};
        std::set<int> invalid = {0, 1, 2, 3, 5, 6, 7, 8};

        for (int i = 0; i < 10; i++) {
            buf[0] = (uint8_t)i;
            try {
                Signature::FromBytes(buf);
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
        uint32_t fingerprint = esk.GetPublicKey().GetFingerprint();
        REQUIRE(fingerprint == 0xa4700b27);
    }
}

TEST_CASE("Signatures")
{
    SECTION("Should sign and verify")
    {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[6] = {28, 20, 102, 229, 1, 157};
        PrivateKey sk1 = PrivateKey::FromSeed(seed, sizeof(seed));
        PublicKey pk1 = sk1.GetPublicKey();
        Signature sig1 = sk1.Sign(message1, sizeof(message1));

        sig1.SetAggregationInfo(
            AggregationInfo::FromMsg(pk1, message1, sizeof(message1)));
        REQUIRE(sig1.Verify());

        uint8_t hash[32];
        Util::Hash256(hash, message1, 7);
        Signature sig2 = sk1.SignPrehashed(hash);
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
        PublicKey pk1 = sk1.GetPublicKey();
        PrivateKey sk2 = PrivateKey(sk1);

        uint8_t skBytes[PrivateKey::PRIVATE_KEY_SIZE];
        sk2.Serialize(skBytes);
        PrivateKey sk4 = PrivateKey::FromBytes(skBytes);

        PublicKey pk2 = PublicKey(pk1);
        Signature sig1 = sk4.Sign(message1, sizeof(message1));
        Signature sig2 = Signature(sig1);

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
        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();
        PublicKey pk3 = PublicKey(pk2);
        PublicKey pk4 = sk3.GetPublicKey();
        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk1.Sign(message1, sizeof(message1));
        Signature sig3 = sk2.Sign(message1, sizeof(message1));
        Signature sig4 = sk3.Sign(message1, sizeof(message1));

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
        PublicKey pk1 = sk1.GetPublicKey();

        uint8_t* skData = Util::SecAlloc<uint8_t>(Signature::SIGNATURE_SIZE);
        sk1.Serialize(skData);
        PrivateKey sk2 = PrivateKey::FromBytes(skData);
        REQUIRE(sk1 == sk2);

        uint8_t pkData[PublicKey::PUBLIC_KEY_SIZE];
        pk1.Serialize(pkData);

        PublicKey pk2 = PublicKey::FromBytes(pkData);
        REQUIRE(pk1 == pk2);

        Signature sig1 = sk1.Sign(message1, sizeof(message1));

        uint8_t sigData[Signature::SIGNATURE_SIZE];
        sig1.Serialize(sigData);

        Signature sig2 = Signature::FromBytes(sigData);
        REQUIRE(sig1 == sig2);
        sig2.SetAggregationInfo(
            AggregationInfo::FromMsg(pk2, message1, sizeof(message1)));

        REQUIRE(sig2.Verify());
        Util::SecFree(skData);

        InsecureSignature sig3 = InsecureSignature::FromBytes(sigData);
        REQUIRE(Signature::FromInsecureSig(sig3) == sig2);
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

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();

        Signature sig2 = sk2.Sign(message1, sizeof(message1));
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

        InsecureSignature sig1 = sk1.SignInsecure(message, sizeof(message));
        InsecureSignature sig2 = sk2.SignInsecure(message, sizeof(message));
        REQUIRE(sig1 != sig2);
        REQUIRE(sig1.Verify({hash}, {sk1.GetPublicKey()}));
        REQUIRE(sig2.Verify({hash}, {sk2.GetPublicKey()}));

        std::vector<InsecureSignature> const sigs = {sig1, sig2};
        std::vector<PublicKey> const pks = {sk1.GetPublicKey(),
                                            sk2.GetPublicKey()};
        InsecureSignature aggSig = InsecureSignature::Aggregate(sigs);
        PublicKey aggPk = PublicKey::AggregateInsecure(pks);
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

        InsecureSignature sig1 = sk1.SignInsecurePrehashed(hash1);
        InsecureSignature sig2 = sk2.SignInsecurePrehashed(hash2);
        REQUIRE(sig1 != sig2);
        REQUIRE(sig1.Verify({hash1}, {sk1.GetPublicKey()}));
        REQUIRE(sig2.Verify({hash2}, {sk2.GetPublicKey()}));

        std::vector<InsecureSignature> const sigs = {sig1, sig2};
        std::vector<PublicKey> const pks = {sk1.GetPublicKey(),
                                            sk2.GetPublicKey()};
        InsecureSignature aggSig = InsecureSignature::Aggregate(sigs);

        // same message verification should fail
        PublicKey aggPk = PublicKey::AggregateInsecure(pks);
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

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message2, sizeof(message2));

        std::vector<Signature> const sigs = {sig1, sig2};
        Signature aggSig = Signature::Aggregate(sigs);

        Signature sig3 = sk1.Sign(message1, sizeof(message1));
        Signature sig4 = sk2.Sign(message2, sizeof(message2));

        std::vector<Signature> const sigs2 = {sig3, sig4};
        Signature aggSig2 = Signature::Aggregate(sigs2);
        REQUIRE(sig1 == sig3);
        REQUIRE(sig2 == sig4);
        REQUIRE(aggSig == aggSig2);
        REQUIRE(sig1 != sig2);

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should securely aggregate many signatures, diff message")
    {
        std::vector<PrivateKey> sks;
        std::vector<Signature> sigs;

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
            const PublicKey pk = sk.GetPublicKey();
            sks.push_back(sk);
            sigs.push_back(sk.Sign(message, sizeof(message)));
            delete[] message;
        }

        Signature aggSig = Signature::Aggregate(sigs);

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should insecurely aggregate many signatures, diff message")
    {
        std::vector<PrivateKey> sks;
        std::vector<PublicKey> pks;
        std::vector<InsecureSignature> sigs;
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
            const PublicKey pk = sk.GetPublicKey();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.SignInsecurePrehashed(hash));
            delete[] message;
        }

        InsecureSignature aggSig = InsecureSignature::Aggregate(sigs);

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
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PublicKey pk2 = sk2.GetPublicKey();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        PublicKey pk3 = sk3.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message1, sizeof(message1));
        Signature sig3 = sk3.Sign(message1, sizeof(message1));

        std::vector<Signature> const sigs = {sig1, sig2, sig3};
        std::vector<PublicKey> const pubKeys = {pk1, pk2, pk3};
        Signature aggSig = Signature::Aggregate(sigs);

        const PublicKey aggPubKey = PublicKey::Aggregate(pubKeys);
        aggSig.SetAggregationInfo(
            AggregationInfo::FromMsg(aggPubKey, message1, sizeof(message1)));
        REQUIRE(aggSig.Verify());
    }

    SECTION("Should securely divide signatures")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PublicKey pk2 = sk2.GetPublicKey();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        PublicKey pk3 = sk3.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message1, sizeof(message1));
        Signature sig3 = sk3.Sign(message1, sizeof(message1));

        std::vector<Signature> sigs = {sig1, sig2, sig3};
        Signature aggSig = Signature::Aggregate(sigs);

        REQUIRE(sig2.Verify());
        REQUIRE(sig3.Verify());
        std::vector<Signature> divisorSigs = {sig2, sig3};

        REQUIRE(aggSig.Verify());

        REQUIRE(aggSig.GetAggregationInfo()->GetPubKeys().size() == 3);
        const Signature aggSig2 = aggSig.DivideBy(divisorSigs);
        REQUIRE(aggSig.GetAggregationInfo()->GetPubKeys().size() == 3);
        REQUIRE(aggSig2.GetAggregationInfo()->GetPubKeys().size() == 1);

        REQUIRE(aggSig.Verify());
        REQUIRE(aggSig2.Verify());
    }

    SECTION("Should securely divide aggregate signatures")
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
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PublicKey pk2 = sk2.GetPublicKey();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        PublicKey pk3 = sk3.GetPublicKey();

        PrivateKey sk4 = PrivateKey::FromSeed(seed4, 32);
        PublicKey pk4 = sk4.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message1, sizeof(message1));
        Signature sig3 = sk3.Sign(message1, sizeof(message1));
        Signature sig4 = sk4.Sign(message2, sizeof(message2));
        Signature sig5 = sk4.Sign(message1, sizeof(message1));
        Signature sig6 = sk2.Sign(message3, sizeof(message3));

        std::vector<Signature> sigsL = {sig1, sig2};
        std::vector<Signature> sigsC = {sig3, sig4};
        std::vector<Signature> sigsR = {sig5, sig6};
        Signature aggSigL = Signature::Aggregate(sigsL);
        Signature aggSigC = Signature::Aggregate(sigsC);
        Signature aggSigR = Signature::Aggregate(sigsR);

        std::vector<Signature> sigsL2 = {aggSigL, aggSigC};
        Signature aggSigL2 = Signature::Aggregate(sigsL2);

        std::vector<Signature> sigsFinal = {aggSigL2, aggSigR};
        Signature aggSigFinal = Signature::Aggregate(sigsFinal);

        REQUIRE(aggSigFinal.Verify());
        REQUIRE(aggSigFinal.GetAggregationInfo()->GetPubKeys().size() == 6);
        std::vector<Signature> divisorSigs = {aggSigL, sig6};
        aggSigFinal = aggSigFinal.DivideBy(divisorSigs);
        REQUIRE(aggSigFinal.GetAggregationInfo()->GetPubKeys().size() == 3);
        REQUIRE(aggSigFinal.Verify());

        // Throws when the m/pk pair is not unique within the aggregate (sig1
        // is in both aggSigL2 and sig1.
        std::vector<Signature> sigsFinal2 = {aggSigL2, aggSigR, sig1};
        Signature aggSigFinal2 = Signature::Aggregate(sigsFinal2);
        std::vector<Signature> divisorSigs2 = {aggSigL};
        std::vector<Signature> divisorSigs3 = {sig6};
        aggSigFinal2 = aggSigFinal2.DivideBy(divisorSigs3);
        REQUIRE_THROWS(aggSigFinal2.DivideBy(divisorSigs));
    }

    SECTION("Should insecurely aggregate many sigs, same message")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t hash1[BLS::MESSAGE_HASH_LEN];

        std::vector<PrivateKey> sks;
        std::vector<PublicKey> pks;
        std::vector<InsecureSignature> sigs;

        Util::Hash256(hash1, message1, sizeof(message1));

        for (int i = 0; i < 70; i++) {
            uint8_t seed[32];
            getRandomSeed(seed);
            PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            const PublicKey pk = sk.GetPublicKey();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.SignInsecure(message1, sizeof(message1)));
        }

        InsecureSignature aggSig = InsecureSignature::Aggregate(sigs);
        const PublicKey aggPubKey = PublicKey::AggregateInsecure(pks);
        REQUIRE(aggSig.Verify({hash1}, {aggPubKey}));
    }

    SECTION("Should securely aggregate many sigs, same message")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};

        std::vector<PrivateKey> sks;
        std::vector<PublicKey> pks;
        std::vector<Signature> sigs;

        for (int i = 0; i < 70; i++) {
            uint8_t seed[32];
            getRandomSeed(seed);
            PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            const PublicKey pk = sk.GetPublicKey();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.Sign(message1, sizeof(message1)));
        }

        Signature aggSig = Signature::Aggregate(sigs);
        const PublicKey aggPubKey = PublicKey::Aggregate(pks);
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
        PublicKey pk1 = sk1.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));

        std::vector<Signature> const sigs = {};
        REQUIRE_THROWS(Signature::Aggregate(sigs));

        sig1.SetAggregationInfo(AggregationInfo());
        std::vector<Signature> const sigs2 = {sig1};
        REQUIRE_THROWS(Signature::Aggregate(sigs2));
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
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PublicKey pk2 = sk2.GetPublicKey();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        PublicKey pk3 = sk3.GetPublicKey();

        PrivateKey sk4 = PrivateKey::FromSeed(seed4, 32);
        PublicKey pk4 = sk4.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message1, sizeof(message1));
        Signature sig3 = sk3.Sign(message2, sizeof(message2));
        Signature sig4 = sk4.Sign(message3, sizeof(message3));
        Signature sig5 = sk3.Sign(message1, sizeof(message1));
        Signature sig6 = sk2.Sign(message1, sizeof(message1));
        Signature sig7 = sk4.Sign(message2, sizeof(message2));

        std::vector<Signature> const sigs = {
            sig1, sig2, sig3, sig4, sig5, sig6, sig7};
        std::vector<PublicKey> const pubKeys = {
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

        // Verifier generates a batch signature for efficiency
        Signature aggSig = Signature::Aggregate(sigs);
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
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PublicKey pk2 = sk2.GetPublicKey();

        PrivateKey sk3 = PrivateKey::FromSeed(seed3, 32);
        PublicKey pk3 = sk3.GetPublicKey();

        PrivateKey sk4 = PrivateKey::FromSeed(seed4, 32);
        PublicKey pk4 = sk4.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message1, sizeof(message1));
        Signature sig3 = sk3.Sign(message2, sizeof(message2));
        Signature sig4 = sk4.Sign(message3, sizeof(message3));
        Signature sig5 = sk3.Sign(message1, sizeof(message1));
        Signature sig6 = sk2.Sign(message1, sizeof(message1));
        Signature sig7 = sk4.Sign(message2, sizeof(message2));

        std::vector<Signature> const sigs = {
            sig1, sig2, sig3, sig4, sig5, sig6, sig7};

        REQUIRE(sig1.Verify());
        REQUIRE(sig3.Verify());
        REQUIRE(sig4.Verify());
        REQUIRE(sig7.Verify());
        std::vector<Signature> cache = {sig1, sig3, sig4, sig7};

        // Verifier generates a batch signature for efficiency
        Signature aggSig = Signature::Aggregate(sigs);

        const Signature aggSig2 = aggSig.DivideBy(cache);
        REQUIRE(aggSig.Verify());
        REQUIRE(aggSig2.Verify());
    }

    SECTION("Should aggregate same message with agg sk")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PublicKey pk1 = sk1.GetPublicKey();

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, 32);
        PublicKey pk2 = sk2.GetPublicKey();

        std::vector<PrivateKey> const privateKeys = {sk1, sk2};
        std::vector<PublicKey> const pubKeys = {pk1, pk2};
        const PrivateKey aggSk = PrivateKey::Aggregate(privateKeys, pubKeys);

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message1, sizeof(message1));

        Signature aggSig2 = aggSk.Sign(message1, sizeof(message1));

        std::vector<Signature> const sigs = {sig1, sig2};
        std::vector<uint8_t*> const messages = {message1, message1};
        std::vector<size_t> const messageLens = {sizeof(message1),
                                                 sizeof(message1)};
        Signature aggSig = Signature::Aggregate(sigs);
        ASSERT(aggSig == aggSig2);

        const PublicKey aggPubKey = PublicKey::Aggregate(pubKeys);
        REQUIRE(aggSig.Verify());
        REQUIRE(aggSig2.Verify());
    }
}

TEST_CASE("HD keys")
{
    SECTION("Should create an extended private key from seed")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));

        ExtendedPrivateKey esk77 = esk.PrivateChild(77 + (1 << 31));
        ExtendedPrivateKey esk77copy = esk.PrivateChild(77 + (1 << 31));

        REQUIRE(esk77 == esk77copy);

        ExtendedPrivateKey esk77nh = esk.PrivateChild(77);

        auto eskLong = esk.PrivateChild((1 << 31) + 5)
                           .PrivateChild(0)
                           .PrivateChild(0)
                           .PrivateChild((1 << 31) + 56)
                           .PrivateChild(70)
                           .PrivateChild(4);
        uint8_t chainCode[32];
        eskLong.GetChainCode().Serialize(chainCode);
    }

    SECTION("Should match derivation through private and public keys")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        PublicKey pk1 = esk.PrivateChild(238757).GetPublicKey();
        PublicKey pk2 = epk.PublicChild(238757).GetPublicKey();

        REQUIRE(pk1 == pk2);

        PrivateKey sk3 = esk.PrivateChild(0)
                             .PrivateChild(3)
                             .PrivateChild(8)
                             .PrivateChild(1)
                             .GetPrivateKey();

        PublicKey pk4 = epk.PublicChild(0)
                            .PublicChild(3)
                            .PublicChild(8)
                            .PublicChild(1)
                            .GetPublicKey();
        REQUIRE(sk3.GetPublicKey() == pk4);

        Signature sig = sk3.Sign(seed, sizeof(seed));

        REQUIRE(sig.Verify());
    }

    SECTION("Should prevent hardened pk derivation")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        ExtendedPrivateKey sk = esk.PrivateChild((1 << 31) + 3);
        REQUIRE_THROWS(epk.PublicChild((1 << 31) + 3));
    }

    SECTION("Should derive public child from parent")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 0, 0, 0};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        ExtendedPublicKey pk1 = esk.PublicChild(13);
        ExtendedPublicKey pk2 = epk.PublicChild(13);

        REQUIRE(pk1 == pk2);
    }

    SECTION("Should cout structures")
    {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 0, 0, 0};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        cout << epk << endl;
        cout << epk.GetPublicKey() << endl;
        cout << epk.GetChainCode() << endl;

        Signature sig1 = esk.GetPrivateKey().Sign(seed, sizeof(seed));
        cout << sig1 << endl;
    }

    SECTION("Should serialize extended keys")
    {
        uint8_t seed[] = {1, 50, 6, 244, 25, 199, 1, 25};
        ExtendedPrivateKey esk =
            ExtendedPrivateKey::FromSeed(seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        PublicKey pk1 = esk.PrivateChild(238757).GetPublicKey();
        PublicKey pk2 = epk.PublicChild(238757).GetPublicKey();

        REQUIRE(pk1 == pk2);

        ExtendedPrivateKey sk3 =
            esk.PrivateChild(0).PrivateChild(3).PrivateChild(8).PrivateChild(1);

        ExtendedPublicKey pk4 =
            epk.PublicChild(0).PublicChild(3).PublicChild(8).PublicChild(1);
        uint8_t buffer1[ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE];
        uint8_t buffer2[ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];
        uint8_t buffer3[ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];

        sk3.Serialize(buffer1);
        sk3.GetExtendedPublicKey().Serialize(buffer2);
        pk4.Serialize(buffer3);
        REQUIRE(
            std::memcmp(
                buffer2,
                buffer3,
                ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE) == 0);
    }
}

TEST_CASE("AggregationInfo")
{
    SECTION("Should create object")
    {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};
        uint8_t message2[8] = {1, 65, 254, 88, 90, 45, 22, 12};
        uint8_t message3[8] = {2, 65, 254, 88, 90, 45, 22, 12};
        uint8_t message4[8] = {3, 65, 254, 88, 90, 45, 22, 12};
        uint8_t message5[8] = {4, 65, 254, 88, 90, 45, 22, 12};
        uint8_t message6[8] = {5, 65, 254, 88, 90, 45, 22, 12};
        uint8_t messageHash1[32];
        uint8_t messageHash2[32];
        uint8_t messageHash3[32];
        uint8_t messageHash4[32];
        uint8_t messageHash5[32];
        uint8_t messageHash6[32];
        Util::Hash256(messageHash1, message1, 7);
        Util::Hash256(messageHash2, message2, 8);
        Util::Hash256(messageHash3, message3, 8);
        Util::Hash256(messageHash4, message4, 8);
        Util::Hash256(messageHash5, message5, 8);
        Util::Hash256(messageHash6, message6, 8);

        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        PrivateKey sk2 = PrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        PrivateKey sk3 = PrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        PrivateKey sk4 = PrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        PrivateKey sk5 = PrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        PrivateKey sk6 = PrivateKey::FromSeed(seed, 32);

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();
        PublicKey pk3 = sk3.GetPublicKey();
        PublicKey pk4 = sk4.GetPublicKey();
        PublicKey pk5 = sk5.GetPublicKey();
        PublicKey pk6 = sk6.GetPublicKey();

        AggregationInfo a1 = AggregationInfo::FromMsgHash(pk1, messageHash1);
        AggregationInfo a2 = AggregationInfo::FromMsgHash(pk2, messageHash2);
        std::vector<AggregationInfo> infosA = {a1, a2};
        std::vector<AggregationInfo> infosAcopy = {a2, a1};

        AggregationInfo a3 = AggregationInfo::FromMsgHash(pk3, messageHash1);
        AggregationInfo a4 = AggregationInfo::FromMsgHash(pk4, messageHash1);
        std::vector<AggregationInfo> infosB = {a3, a4};
        std::vector<AggregationInfo> infosBcopy = {a4, a3};
        std::vector<AggregationInfo> infosC = {a1, a2, a3, a4};

        AggregationInfo a5 = AggregationInfo::MergeInfos(infosA);
        AggregationInfo a5b = AggregationInfo::MergeInfos(infosAcopy);
        AggregationInfo a6 = AggregationInfo::MergeInfos(infosB);
        AggregationInfo a6b = AggregationInfo::MergeInfos(infosBcopy);
        std::vector<AggregationInfo> infosD = {a5, a6};

        AggregationInfo a7 = AggregationInfo::MergeInfos(infosC);
        AggregationInfo a8 = AggregationInfo::MergeInfos(infosD);

        REQUIRE(a5 == a5b);
        REQUIRE(a5 != a6);
        REQUIRE(a6 == a6b);

        std::vector<AggregationInfo> infosE = {a1, a3, a4};
        AggregationInfo a9 = AggregationInfo::MergeInfos(infosE);
        std::vector<AggregationInfo> infosF = {a2, a9};
        AggregationInfo a10 = AggregationInfo::MergeInfos(infosF);

        REQUIRE(a10 == a7);

        AggregationInfo a11 = AggregationInfo::FromMsgHash(pk1, messageHash1);
        AggregationInfo a12 = AggregationInfo::FromMsgHash(pk2, messageHash2);
        AggregationInfo a13 = AggregationInfo::FromMsgHash(pk3, messageHash3);
        AggregationInfo a14 = AggregationInfo::FromMsgHash(pk4, messageHash4);
        AggregationInfo a15 = AggregationInfo::FromMsgHash(pk5, messageHash5);
        AggregationInfo a16 = AggregationInfo::FromMsgHash(pk6, messageHash6);
        AggregationInfo a17 = AggregationInfo::FromMsgHash(pk6, messageHash5);
        AggregationInfo a18 = AggregationInfo::FromMsgHash(pk5, messageHash6);

        // Tree L
        std::vector<AggregationInfo> L1 = {a15, a17};
        std::vector<AggregationInfo> L2 = {a11, a13};
        std::vector<AggregationInfo> L3 = {a18, a14};

        AggregationInfo a19 = AggregationInfo::MergeInfos(L1);
        AggregationInfo a20 = AggregationInfo::MergeInfos(L2);
        AggregationInfo a21 = AggregationInfo::MergeInfos(L3);

        std::vector<AggregationInfo> L4 = {a21, a16};
        std::vector<AggregationInfo> L5 = {a19, a20};
        AggregationInfo a22 = AggregationInfo::MergeInfos(L4);
        AggregationInfo a23 = AggregationInfo::MergeInfos(L5);

        std::vector<AggregationInfo> L6 = {a22, a12};
        AggregationInfo a24 = AggregationInfo::MergeInfos(L6);
        std::vector<AggregationInfo> L7 = {a23, a24};
        AggregationInfo LFinal = AggregationInfo::MergeInfos(L7);

        // Tree R
        std::vector<AggregationInfo> R1 = {a17, a12, a11, a15};
        std::vector<AggregationInfo> R2 = {a14, a18};

        AggregationInfo a25 = AggregationInfo::MergeInfos(R1);
        AggregationInfo a26 = AggregationInfo::MergeInfos(R2);

        std::vector<AggregationInfo> R3 = {a26, a16};

        AggregationInfo a27 = AggregationInfo::MergeInfos(R3);

        std::vector<AggregationInfo> R4 = {a27, a13};
        AggregationInfo a28 = AggregationInfo::MergeInfos(R4);
        std::vector<AggregationInfo> R5 = {a25, a28};

        AggregationInfo RFinal = AggregationInfo::MergeInfos(R5);

        REQUIRE(LFinal == RFinal);
    }

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

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message2, sizeof(message2));
        Signature sig3 = sk2.Sign(message1, sizeof(message1));
        Signature sig4 = sk1.Sign(message3, sizeof(message3));
        Signature sig5 = sk1.Sign(message4, sizeof(message4));
        Signature sig6 = sk1.Sign(message1, sizeof(message1));

        std::vector<Signature> const sigsL = {sig1, sig2};
        std::vector<PublicKey> const pksL = {pk1, pk2};
        const Signature aggSigL = Signature::Aggregate(sigsL);

        std::vector<Signature> const sigsR = {sig3, sig4, sig6};
        const Signature aggSigR = Signature::Aggregate(sigsR);

        std::vector<PublicKey> pk1Vec = {pk1};

        std::vector<Signature> sigs = {aggSigL, aggSigR, sig5};

        const Signature aggSig = Signature::Aggregate(sigs);

        REQUIRE(aggSig.Verify());
    }

    SECTION("Should aggregate with multiple levels, degenerate")
    {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        PrivateKey sk1 = PrivateKey::FromSeed(seed, 32);
        PublicKey pk1 = sk1.GetPublicKey();
        Signature aggSig = sk1.Sign(message1, sizeof(message1));

        for (size_t i = 0; i < 10; i++) {
            getRandomSeed(seed);
            PrivateKey sk = PrivateKey::FromSeed(seed, 32);
            PublicKey pk = sk.GetPublicKey();
            Signature sig = sk.Sign(message1, sizeof(message1));
            std::vector<Signature> sigs = {aggSig, sig};
            aggSig = Signature::Aggregate(sigs);
        }
        REQUIRE(aggSig.Verify());
        uint8_t sigSerialized[Signature::SIGNATURE_SIZE];
        aggSig.Serialize(sigSerialized);

        const Signature aggSig2 = Signature::FromBytes(sigSerialized);
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

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();

        Signature sig1 = sk1.Sign(message1, sizeof(message1));
        Signature sig2 = sk2.Sign(message2, sizeof(message2));
        Signature sig3 = sk2.Sign(message3, sizeof(message4));
        Signature sig4 = sk1.Sign(message4, sizeof(message4));

        std::vector<Signature> const sigsL = {sig1, sig2};
        std::vector<PublicKey> const pksL = {pk1, pk2};
        std::vector<uint8_t*> const messagesL = {message1, message2};
        std::vector<size_t> const messageLensL = {sizeof(message1),
                                                  sizeof(message2)};
        const Signature aggSigL = Signature::Aggregate(sigsL);

        std::vector<Signature> const sigsR = {sig3, sig4};
        std::vector<PublicKey> const pksR = {pk2, pk1};
        std::vector<uint8_t*> const messagesR = {message3, message4};
        std::vector<size_t> const messageLensR = {sizeof(message3),
                                                  sizeof(message4)};
        const Signature aggSigR = Signature::Aggregate(sigsR);

        std::vector<Signature> sigs = {aggSigL, aggSigR};
        std::vector<std::vector<PublicKey>> pks = {pksL, pksR};
        std::vector<std::vector<uint8_t*>> messages = {messagesL, messagesR};
        std::vector<std::vector<size_t>> messageLens = {messageLensL,
                                                        messageLensR};

        const Signature aggSig = Signature::Aggregate(sigs);

        std::vector<PublicKey> allPks = {pk1, pk2, pk2, pk1};
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
        PublicKey pk1 = sk1.GetPublicKey();
        std::cout << "PK: " << pk1 << std::endl;

        uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash, message1, 7);
        vector<const uint8_t*> messageHashes = {messageHash};
        vector<PublicKey> pks = {pk1};

        const PrependSignature sig1 = sk1.SignPrepend(message1, 7);
        REQUIRE(sig1.Verify(messageHashes, pks));

        uint8_t sigData[PrependSignature::SIGNATURE_SIZE];
        uint8_t sigData2[PrependSignature::SIGNATURE_SIZE];
        sig1.Serialize(sigData);
        sig1.GetInsecureSig().Serialize(sigData2);
        REQUIRE(
            memcmp(sigData, sigData2, PrependSignature::SIGNATURE_SIZE) != 0);

        PrependSignature sig2 = PrependSignature::FromBytes(sigData);
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

        PublicKey pk1 = sk1.GetPublicKey();
        PublicKey pk2 = sk2.GetPublicKey();
        PublicKey pk3 = sk3.GetPublicKey();

        PrependSignature sig1 = sk1.SignPrepend(message1, 7);
        PrependSignature sig2 = sk2.SignPrepend(message1, 7);
        PrependSignature sig3 = sk3.SignPrepend(message2, 7);

        uint8_t messageHash1[BLS::MESSAGE_HASH_LEN];
        uint8_t messageHash2[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash1, message1, 7);
        Util::Hash256(messageHash2, message2, 7);
        vector<const uint8_t*> messageHashes1 = {messageHash1};
        vector<const uint8_t*> messageHashes2 = {messageHash2};
        vector<const uint8_t*> messageHashes = {
            messageHash1, messageHash1, messageHash2};
        vector<PublicKey> pks1 = {pk1};
        vector<PublicKey> pks2 = {pk2};
        vector<PublicKey> pks3 = {pk3};
        vector<PublicKey> pks = {pk1, pk2, pk3};

        REQUIRE(sig1.Verify(messageHashes1, pks1));
        REQUIRE(sig2.Verify(messageHashes1, pks2));
        REQUIRE(sig3.Verify(messageHashes2, pks3));

        vector<PrependSignature> sigs = {sig1, sig2, sig3};

        PrependSignature agg = PrependSignature::Aggregate(sigs);
        REQUIRE(agg.Verify(messageHashes, pks));

        vector<PublicKey> pksWrong = {pk1, pk2, pk2};
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
        PublicKey pk = sk.GetPublicKey();

        uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};

        Signature sig = sk.Sign(msg, sizeof(msg));

        uint8_t skBytes[PrivateKey::PRIVATE_KEY_SIZE];  // 32 byte array
        uint8_t pkBytes[PublicKey::PUBLIC_KEY_SIZE];    // 48 byte array
        uint8_t sigBytes[Signature::SIGNATURE_SIZE];    // 96 byte array

        sk.Serialize(skBytes);    // 32 bytes
        pk.Serialize(pkBytes);    // 48 bytes
        sig.Serialize(sigBytes);  // 96 bytes
        // Takes array of 32 bytes
        sk = PrivateKey::FromBytes(skBytes);

        // Takes array of 48 bytes
        pk = PublicKey::FromBytes(pkBytes);

        // Takes array of 96 bytes
        sig = Signature::FromBytes(sigBytes);
        // Add information required for verification, to sig object
        sig.SetAggregationInfo(AggregationInfo::FromMsg(pk, msg, sizeof(msg)));

        bool ok = sig.Verify();
        // Generate some more private keys
        seed[0] = 1;
        PrivateKey sk1 = PrivateKey::FromSeed(seed, sizeof(seed));
        seed[0] = 2;
        PrivateKey sk2 = PrivateKey::FromSeed(seed, sizeof(seed));

        // Generate first sig
        PublicKey pk1 = sk1.GetPublicKey();
        Signature sig1 = sk1.Sign(msg, sizeof(msg));

        // Generate second sig
        PublicKey pk2 = sk2.GetPublicKey();
        Signature sig2 = sk2.Sign(msg, sizeof(msg));

        // Aggregate signatures together
        std::vector<Signature> sigs = {sig1, sig2};
        Signature aggSig = Signature::Aggregate(sigs);

        // For same message, public keys can be aggregated into one.
        // The signature can be verified the same as a single signature,
        // using this public key.
        std::vector<PublicKey> pubKeys = {pk1, pk2};
        PublicKey aggPubKey = PublicKey::Aggregate(pubKeys);
        // Generate one more key
        seed[0] = 3;
        PrivateKey sk3 = PrivateKey::FromSeed(seed, sizeof(seed));
        PublicKey pk3 = sk3.GetPublicKey();
        uint8_t msg2[] = {100, 2, 254, 88, 90, 45, 23};

        // Generate the signatures, assuming we have 3 private keys
        sig1 = sk1.Sign(msg, sizeof(msg));
        sig2 = sk2.Sign(msg, sizeof(msg));
        Signature sig3 = sk3.Sign(msg2, sizeof(msg2));

        // They can be noninteractively combined by anyone
        // Aggregation below can also be done by the verifier, to
        // make batch verification more efficient
        std::vector<Signature> sigsL = {sig1, sig2};
        Signature aggSigL = Signature::Aggregate(sigsL);

        // Arbitrary trees of aggregates
        std::vector<Signature> sigsFinal = {aggSigL, sig3};
        Signature aggSigFinal = Signature::Aggregate(sigsFinal);

        // Serialize the final signature
        aggSigFinal.Serialize(sigBytes);
        // Deserialize aggregate signature
        aggSigFinal = Signature::FromBytes(sigBytes);

        // Create aggregation information (or deserialize it)
        AggregationInfo a1 = AggregationInfo::FromMsg(pk1, msg, sizeof(msg));
        AggregationInfo a2 = AggregationInfo::FromMsg(pk2, msg, sizeof(msg));
        AggregationInfo a3 = AggregationInfo::FromMsg(pk3, msg2, sizeof(msg2));
        std::vector<AggregationInfo> infos = {a1, a2};
        AggregationInfo a1a2 = AggregationInfo::MergeInfos(infos);
        std::vector<AggregationInfo> infos2 = {a1a2, a3};
        AggregationInfo aFinal = AggregationInfo::MergeInfos(infos2);

        // Verify final signature using the aggregation info
        aggSigFinal.SetAggregationInfo(aFinal);
        ok = aggSigFinal.Verify();

        // If you previously verified a signature, you can also divide
        // the aggregate signature by the signature you already verified.
        ok = aggSigL.Verify();
        std::vector<Signature> cache = {aggSigL};
        aggSigFinal = aggSigFinal.DivideBy(cache);

        // Final verification is now more efficient
        ok = aggSigFinal.Verify();

        std::vector<PrivateKey> privateKeysList = {sk1, sk2};
        std::vector<PublicKey> pubKeysList = {pk1, pk2};

        // Create an aggregate private key, that can generate
        // aggregate signatures
        const PrivateKey aggSk =
            PrivateKey::Aggregate(privateKeysList, pubKeysList);

        Signature aggSig3 = aggSk.Sign(msg, sizeof(msg));

        PrependSignature prepend1 = sk1.SignPrepend(msg, sizeof(msg));
        PrependSignature prepend2 = sk2.SignPrepend(msg, sizeof(msg));
        std::vector<PublicKey> prependPubKeys = {pk1, pk2};
        uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(messageHash, msg, sizeof(msg));
        std::vector<const uint8_t*> hashes = {messageHash, messageHash};
        std::vector<PrependSignature> prependSigs = {prepend1, prepend2};
        PrependSignature prependAgg = PrependSignature::Aggregate(prependSigs);
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

        // PublicKey commits[N][T]
        // PrivateKey frags[N][N]
        std::vector<std::vector<PublicKey>> commits;
        std::vector<std::vector<PrivateKey>> frags;
        for (size_t i = 0; i < N; ++i) {
            commits.emplace_back(std::vector<PublicKey>());
            frags.emplace_back(std::vector<PrivateKey>());
            for (size_t j = 0; j < N; ++j) {
                if (j < T) {
                    g1_t g;
                    commits[i].emplace_back(PublicKey::FromG1(&g));
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
        // masterPubkey = PublicKey::AggregateInsecure(...)
        // They also create their secret share from all secret
        // fragments received (now verified):
        // secretShare = PrivateKey::AggregateInsecure(...)

        PublicKey masterPubkey = PublicKey::AggregateInsecure(
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

        // 4a. Player P creates a pre-multiplied signature share wrt T players:
        // sigShare = Threshold::SignWithCoefficient(...)
        // These signature shares can be combined to sign the msg:
        // signature = InsecureSignature::Aggregate(...)
        // The advantage of this approach is that forming the final signature
        // no longer requires information about the players.

        uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t hash[32];
        Util::Hash256(hash, msg, sizeof(msg));

        size_t players[] = {1, 3};
        // For example, players 1 and 3 sign.
        // As we have verified the coefficients through the commitments given,
        // using InsecureSignature is okay.
        InsecureSignature sigShareC1 = Threshold::SignWithCoefficient(
            secretShare1, msg, (size_t)sizeof(msg), (size_t)1, players, T);
        InsecureSignature sigShareC3 = Threshold::SignWithCoefficient(
            secretShare3, msg, (size_t)sizeof(msg), (size_t)3, players, T);

        InsecureSignature signature =
            InsecureSignature::Aggregate({sigShareC1, sigShareC3});

        REQUIRE(signature.Verify({hash}, {masterPubkey}));

        // 4b. Alternatively, players may sign the message blindly, creating
        // a unit signature share: sigShare = secretShare.SignInsecure(...)
        // These signatures may be combined with lagrange coefficients to
        // sign the message: signature = Threshold::AggregateUnitSigs(...)
        // The advantage to this approach is that each player does not need
        // to know the final list of signatories.

        // For example, players 1 and 3 sign.
        InsecureSignature sigShareU1 =
            secretShare1.SignInsecure(msg, (size_t)sizeof(msg));
        InsecureSignature sigShareU3 =
            secretShare3.SignInsecure(msg, (size_t)sizeof(msg));
        InsecureSignature signature2 = Threshold::AggregateUnitSigs(
            {sigShareU1, sigShareU3}, msg, (size_t)sizeof(msg), players, T);

        REQUIRE(signature2.Verify({hash}, {masterPubkey}));
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
        G2Element sig1 = BasicSchemeMPL::SignNative(sk1, msg1);
        vector<uint8_t> sig1v = BasicSchemeMPL::Sign(sk1, msg1);
        std::cout << "PK1: " << pk1 << "\n";
        std::cout << "SIG1: " << sig1 << "\n";
        G2Element sig0 = BasicSchemeMPL::SignNative(sk1, msg0);
        std::cout << "SIG0: " << sig0 << "\n";
    }
    */

    SECTION("Basic Scheme")
    {
        uint8_t seed1[5] = {1, 2, 3, 4, 5};
        uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};
        vector<uint8_t> msg1 = {7, 8, 9};
        vector<uint8_t> msg2 = {10, 11, 12};
        vector<vector<uint8_t>> msgs = {msg1, msg2};

        PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
        G1Element pk1 = BasicSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = BasicSchemeMPL::SkToPk(sk1);
        G2Element sig1 = BasicSchemeMPL::SignNative(sk1, msg1);
        vector<uint8_t> sig1v = BasicSchemeMPL::Sign(sk1, msg1);

        REQUIRE(BasicSchemeMPL::Verify(pk1, msg1, sig1));
        REQUIRE(BasicSchemeMPL::Verify(pk1v, msg1, sig1v));

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));
        G1Element pk2 = BasicSchemeMPL::SkToG1(sk2);
        vector<uint8_t> pk2v = BasicSchemeMPL::SkToPk(sk2);
        G2Element sig2 = BasicSchemeMPL::SignNative(sk2, msg2);
        vector<uint8_t> sig2v = BasicSchemeMPL::Sign(sk2, msg2);

        // Wrong signature
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
        uint8_t seed1[5] = {1, 2, 3, 4, 5};
        uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};
        vector<uint8_t> msg1 = {7, 8, 9};
        vector<uint8_t> msg2 = {10, 11, 12};
        vector<vector<uint8_t>> msgs = {msg1, msg2};

        PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
        G1Element pk1 = AugSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = AugSchemeMPL::SkToPk(sk1);
        G2Element sig1 = AugSchemeMPL::SignNative(sk1, msg1);
        vector<uint8_t> sig1v = AugSchemeMPL::Sign(sk1, msg1);

        REQUIRE(AugSchemeMPL::Verify(pk1, msg1, sig1));
        REQUIRE(AugSchemeMPL::Verify(pk1v, msg1, sig1v));

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));
        G1Element pk2 = AugSchemeMPL::SkToG1(sk2);
        vector<uint8_t> pk2v = AugSchemeMPL::SkToPk(sk2);
        G2Element sig2 = AugSchemeMPL::SignNative(sk2, msg2);
        vector<uint8_t> sig2v = AugSchemeMPL::Sign(sk2, msg2);

        // Wrong signature
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
        uint8_t seed1[5] = {1, 2, 3, 4, 5};
        uint8_t seed2[6] = {1, 2, 3, 4, 5, 6};
        vector<uint8_t> msg1 = {7, 8, 9};
        vector<uint8_t> msg2 = {10, 11, 12};
        vector<vector<uint8_t>> msgs = {msg1, msg2};

        PrivateKey sk1 = PrivateKey::FromSeed(seed1, sizeof(seed1));
        G1Element pk1 = PopSchemeMPL::SkToG1(sk1);
        vector<uint8_t> pk1v = PopSchemeMPL::SkToPk(sk1);
        G2Element sig1 = PopSchemeMPL::SignNative(sk1, msg1);
        vector<uint8_t> sig1v = PopSchemeMPL::Sign(sk1, msg1);

        REQUIRE(PopSchemeMPL::Verify(pk1, msg1, sig1));
        REQUIRE(PopSchemeMPL::Verify(pk1v, msg1, sig1v));

        PrivateKey sk2 = PrivateKey::FromSeed(seed2, sizeof(seed2));
        G1Element pk2 = PopSchemeMPL::SkToG1(sk2);
        vector<uint8_t> pk2v = PopSchemeMPL::SkToPk(sk2);
        G2Element sig2 = PopSchemeMPL::SignNative(sk2, msg2);
        vector<uint8_t> sig2v = PopSchemeMPL::Sign(sk2, msg2);

        // Wrong signature
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
        G2Element sig2_same = PopSchemeMPL::SignNative(sk2, msg1);
        vector<uint8_t> sig2v_same = PopSchemeMPL::Sign(sk2, msg1);
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
