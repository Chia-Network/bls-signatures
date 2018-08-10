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
#include "catch.hpp"
#include "bls.hpp"
#include "test-utils.hpp"

using std::string;
using std::vector;
using std::cout;
using std::endl;

TEST_CASE("Key generation") {
    SECTION("Should generate a keypair from a seed") {
        uint8_t seed[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};


        BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, sizeof(seed));
        BLSPublicKey pk = sk.GetPublicKey();
        REQUIRE(relic::core_get()->code == STS_OK);
        REQUIRE(pk.GetFingerprint() == 0xddad59bb);
    }
}

TEST_CASE("Util tests") {
    SECTION("Should convert an int to four bytes") {
        uint32_t x = 1024;
        uint8_t expected[4] = {0x00, 0x00, 0x04, 0x00};
        uint8_t result[4];
        BLSUtil::IntToFourBytes(result, x);
        REQUIRE(result[0] == expected[0]);
        REQUIRE(result[1] == expected[1]);
        REQUIRE(result[2] == expected[2]);
        REQUIRE(result[3] == expected[3]);
        uint32_t again = BLSUtil::FourBytesToInt(result);
        REQUIRE(again == x);
    }

    SECTION("Should calculate public key fingerprints") {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));
        uint32_t fingerprint = esk.GetPublicKey().GetFingerprint();
        REQUIRE(fingerprint == 0xa4700b27);
    }
}

TEST_CASE("Signatures") {
    SECTION("Should sign and verify") {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[6] = {28, 20, 102, 229, 1, 157};
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, sizeof(seed));
        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));

        sig1.SetAggregationInfo(
                AggregationInfo::FromMsg(pk1, message1, sizeof(message1)));
        REQUIRE(BLS::Verify(sig1));

        uint8_t hash[32];
        BLSUtil::Hash256(hash, message1, 7);
        BLSSignature sig2 = sk1.SignPrehashed(hash);
        sig2.SetAggregationInfo(
                AggregationInfo::FromMsg(pk1, message1, sizeof(message1)));
        REQUIRE(sig1 == sig2);
        REQUIRE(BLS::Verify(sig2));
    }

    SECTION("Should use copy constructor") {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[32];
        getRandomSeed(seed);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPrivateKey sk2 = BLSPrivateKey(sk1);

        uint8_t skBytes[BLSPrivateKey::PRIVATE_KEY_SIZE];
        sk2.Serialize(skBytes);
        BLSPrivateKey sk4 = BLSPrivateKey::FromBytes(skBytes);

        BLSPublicKey pk2 = BLSPublicKey(pk1);
        BLSSignature sig1 = sk4.Sign(message1, sizeof(message1));
        BLSSignature sig2 = BLSSignature(sig1);

        REQUIRE(BLS::Verify(sig2));
    }

    SECTION("Should use operators") {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPrivateKey sk2 = BLSPrivateKey(sk1);
        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed3, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPublicKey pk2 = sk2.GetPublicKey();
        BLSPublicKey pk3 = BLSPublicKey(pk2);
        BLSPublicKey pk4 = sk3.GetPublicKey();
        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig3 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig4 = sk3.Sign(message1, sizeof(message1));

        REQUIRE(sk1 == sk2);
        REQUIRE(sk1 != sk3);
        REQUIRE(pk1 == pk2);
        REQUIRE(pk2 == pk3);
        REQUIRE(pk1 != pk4);
        REQUIRE(sig1 == sig2);
        REQUIRE(sig2 == sig3);
        REQUIRE(sig3 != sig4);

        REQUIRE(pk1[0] == pk2[0]);
        REQUIRE(pk1[15] == pk2[15]);
        REQUIRE(sig1[16] == sig2[16]);
        REQUIRE(sig1.begin() + sig1.size() == sig1.end());
        REQUIRE(sk1.begin() + sk1.size() == sk1.end());
        REQUIRE(pk1.begin() + pk1.size() == pk1.end());
    }

    SECTION("Should serialize and deserialize") {
        uint8_t message1[7] = {1, 65, 254, 88, 90, 45, 22};

        uint8_t seed[32];
        getRandomSeed(seed);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        uint8_t* skData = BLSUtil::SecAlloc<uint8_t>(
                BLSSignature::SIGNATURE_SIZE);
        sk1.Serialize(skData);
        BLSPrivateKey sk2 = BLSPrivateKey::FromBytes(skData);
        REQUIRE(sk1 == sk2);

        uint8_t pkData[BLSPublicKey::PUBLIC_KEY_SIZE];
        pk1.Serialize(pkData);

        BLSPublicKey pk2 = BLSPublicKey::FromBytes(pkData);
        REQUIRE(pk1 == pk2);

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));

        uint8_t sigData[BLSSignature::SIGNATURE_SIZE];
        sig1.Serialize(sigData);

        BLSSignature sig2 = BLSSignature::FromBytes(sigData);
        REQUIRE(sig1 == sig2);
        sig2.SetAggregationInfo(AggregationInfo::FromMsg(
                pk2, message1, sizeof(message1)));

        REQUIRE(BLS::Verify(sig2));
        BLSUtil::SecFree(skData);
    }

    SECTION("Should throw on a bad private key") {
        uint8_t seed[32];
        getRandomSeed(seed);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        uint8_t* skData = BLSUtil::SecAlloc<uint8_t>(
                BLSSignature::SIGNATURE_SIZE);
        sk1.Serialize(skData);
        skData[0] = 255;
        REQUIRE_THROWS(BLSPrivateKey::FromBytes(skData));

        BLSUtil::SecFree(skData);
    }

    SECTION("Should not validate a bad sig") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 22};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);

        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));
        sig2.SetAggregationInfo(AggregationInfo::FromMsg(
                pk1, message1, sizeof(message1)));

        REQUIRE(BLS::Verify(sig2) == false);
    }

    SECTION("Should aggregate and verify aggregate") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[7] = {192, 29, 2, 0, 0, 45, 23};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);

        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message2, sizeof(message2));

        std::vector<BLSSignature> const sigs = {sig1, sig2};
        BLSSignature aggSig = BLS::AggregateSigs(sigs);

        BLSSignature sig3 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig4 = sk2.Sign(message2, sizeof(message2));

        std::vector<BLSSignature> const sigs2 = {sig3, sig4};
        BLSSignature aggSig2 = BLS::AggregateSigs(sigs2);
        REQUIRE(sig1 == sig3);
        REQUIRE(sig2 == sig4);
        REQUIRE(aggSig == aggSig2);
        REQUIRE(sig1 != sig2);

        REQUIRE(BLS::Verify(aggSig));
    }

    SECTION("Should aggregate many signatures, diff message") {
        std::vector<BLSPrivateKey> sks;
        std::vector<BLSSignature> sigs;

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
            const BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
            const BLSPublicKey pk = sk.GetPublicKey();
            sks.push_back(sk);
            sigs.push_back(sk.Sign(message, sizeof(message)));
            delete[] message;
        }

        BLSSignature aggSig = BLS::AggregateSigs(sigs);

        REQUIRE(BLS::Verify(aggSig));
    }

    SECTION("Should aggregate same message") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed3, 32);
        BLSPublicKey pk3 = sk3.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig3 = sk3.Sign(message1, sizeof(message1));

        std::vector<BLSSignature> const sigs = {sig1, sig2, sig3};
        std::vector<BLSPublicKey> const pubKeys = {pk1, pk2, pk3};
        BLSSignature aggSig = BLS::AggregateSigs(sigs);

        const BLSPublicKey aggPubKey = BLS::AggregatePubKeys(pubKeys, true);
        aggSig.SetAggregationInfo(AggregationInfo::FromMsg(
                aggPubKey, message1, sizeof(message1)));
        REQUIRE(BLS::Verify(aggSig));
    }

    SECTION("Should divide signatures") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);
        uint8_t seed3[32];
        getRandomSeed(seed3);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed3, 32);
        BLSPublicKey pk3 = sk3.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig3 = sk3.Sign(message1, sizeof(message1));

        std::vector<BLSSignature> sigs = {sig1, sig2, sig3};
        BLSSignature aggSig = BLS::AggregateSigs(sigs);

        REQUIRE(BLS::Verify(sig2));
        REQUIRE(BLS::Verify(sig3));
        std::vector<BLSSignature> divisorSigs = {sig2, sig3};

        REQUIRE(BLS::Verify(aggSig));

        REQUIRE(aggSig.GetAggregationInfo()->GetPubKeys().size() == 3);
        const BLSSignature aggSig2 = aggSig.DivideBy(divisorSigs);
        REQUIRE(aggSig.GetAggregationInfo()->GetPubKeys().size() == 3);
        REQUIRE(aggSig2.GetAggregationInfo()->GetPubKeys().size() == 1);

        REQUIRE(BLS::Verify(aggSig));
        REQUIRE(BLS::Verify(aggSig2));
    }

    SECTION("Should divide aggregate signatures") {
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

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed3, 32);
        BLSPublicKey pk3 = sk3.GetPublicKey();

        BLSPrivateKey sk4 = BLSPrivateKey::FromSeed(seed4, 32);
        BLSPublicKey pk4 = sk4.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig3 = sk3.Sign(message1, sizeof(message1));
        BLSSignature sig4 = sk4.Sign(message2, sizeof(message2));
        BLSSignature sig5 = sk4.Sign(message1, sizeof(message1));
        BLSSignature sig6 = sk2.Sign(message3, sizeof(message3));

        std::vector<BLSSignature> sigsL = {sig1, sig2};
        std::vector<BLSSignature> sigsC = {sig3, sig4};
        std::vector<BLSSignature> sigsR = {sig5, sig6};
        BLSSignature aggSigL = BLS::AggregateSigs(sigsL);
        BLSSignature aggSigC = BLS::AggregateSigs(sigsC);
        BLSSignature aggSigR = BLS::AggregateSigs(sigsR);

        std::vector<BLSSignature> sigsL2 = {aggSigL, aggSigC};
        BLSSignature aggSigL2 = BLS::AggregateSigs(sigsL2);

        std::vector<BLSSignature> sigsFinal = {aggSigL2, aggSigR};
        BLSSignature aggSigFinal = BLS::AggregateSigs(sigsFinal);

        REQUIRE(BLS::Verify(aggSigFinal));
        REQUIRE(aggSigFinal.GetAggregationInfo()->GetPubKeys().size() == 6);
        std::vector<BLSSignature> divisorSigs = {aggSigL, sig6};
        aggSigFinal = aggSigFinal.DivideBy(divisorSigs);
        REQUIRE(aggSigFinal.GetAggregationInfo()->GetPubKeys().size() == 3);
        REQUIRE(BLS::Verify(aggSigFinal));

        // Throws when the m/pk pair is not unique within the aggregate (sig1
        // is in both aggSigL2 and sig1.
        std::vector<BLSSignature> sigsFinal2 = {aggSigL2, aggSigR, sig1};
        BLSSignature aggSigFinal2 = BLS::AggregateSigs(sigsFinal2);
        std::vector<BLSSignature> divisorSigs2 = {aggSigL};
        std::vector<BLSSignature> divisorSigs3 = {sig6};
        aggSigFinal2 = aggSigFinal2.DivideBy(divisorSigs3);
        REQUIRE_THROWS(aggSigFinal2.DivideBy(divisorSigs));
    }

    SECTION("Should aggregate many sigs, same message") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};

        std::vector<BLSPrivateKey> sks;
        std::vector<BLSPublicKey> pks;
        std::vector<BLSSignature> sigs;

        for (int i = 0; i < 70; i++) {
            uint8_t seed[32];
            getRandomSeed(seed);
            BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
            const BLSPublicKey pk = sk.GetPublicKey();
            sks.push_back(sk);
            pks.push_back(pk);
            sigs.push_back(sk.Sign(message1, sizeof(message1)));
        }

        BLSSignature aggSig = BLS::AggregateSigs(sigs);
        const BLSPublicKey aggPubKey = BLS::AggregatePubKeys(pks, true);
        aggSig.SetAggregationInfo(AggregationInfo::FromMsg(
                aggPubKey, message1, sizeof(message1)));
        REQUIRE(BLS::Verify(aggSig));
    }

    SECTION("Should have at least one sig, with AggregationInfo") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));

        std::vector<BLSSignature> const sigs = {};
        REQUIRE_THROWS(BLS::AggregateSigs(sigs));

        sig1.SetAggregationInfo(AggregationInfo());
        std::vector<BLSSignature> const sigs2 = {sig1};
        REQUIRE_THROWS(BLS::AggregateSigs(sigs2));
    }

    SECTION("Should perform batch verification") {
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

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed3, 32);
        BLSPublicKey pk3 = sk3.GetPublicKey();

        BLSPrivateKey sk4 = BLSPrivateKey::FromSeed(seed4, 32);
        BLSPublicKey pk4 = sk4.GetPublicKey();


        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig3 = sk3.Sign(message2, sizeof(message2));
        BLSSignature sig4 = sk4.Sign(message3, sizeof(message3));
        BLSSignature sig5 = sk3.Sign(message1, sizeof(message1));
        BLSSignature sig6 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig7 = sk4.Sign(message2, sizeof(message2));

        std::vector<BLSSignature> const sigs =
                {sig1, sig2, sig3, sig4, sig5, sig6, sig7};
        std::vector<BLSPublicKey> const pubKeys =
                {pk1, pk2, pk3, pk4, pk3, pk2, pk4};
        std::vector<uint8_t*> const messages =
                {message1, message1, message2, message3, message1,
                 message1, message2};
        std::vector<size_t> const messageLens =
                {sizeof(message1), sizeof(message1), sizeof(message2),
                 sizeof(message3), sizeof(message1), sizeof(message1),
                 sizeof(message2)};

        // Verifier generates a batch signature for efficiency
        BLSSignature aggSig = BLS::AggregateSigs(sigs);
        REQUIRE(BLS::Verify(aggSig));
    }

    SECTION("Should perform batch verification with cache optimization") {
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

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed3, 32);
        BLSPublicKey pk3 = sk3.GetPublicKey();

        BLSPrivateKey sk4 = BLSPrivateKey::FromSeed(seed4, 32);
        BLSPublicKey pk4 = sk4.GetPublicKey();


        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig3 = sk3.Sign(message2, sizeof(message2));
        BLSSignature sig4 = sk4.Sign(message3, sizeof(message3));
        BLSSignature sig5 = sk3.Sign(message1, sizeof(message1));
        BLSSignature sig6 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig7 = sk4.Sign(message2, sizeof(message2));

        std::vector<BLSSignature> const sigs =
                {sig1, sig2, sig3, sig4, sig5, sig6, sig7};

        REQUIRE(BLS::Verify(sig1));
        REQUIRE(BLS::Verify(sig3));
        REQUIRE(BLS::Verify(sig4));
        REQUIRE(BLS::Verify(sig7));
        std::vector<BLSSignature> cache = {sig1, sig3, sig4, sig7};

        // Verifier generates a batch signature for efficiency
        BLSSignature aggSig = BLS::AggregateSigs(sigs);

        const BLSSignature aggSig2 = aggSig.DivideBy(cache);
        REQUIRE(BLS::Verify(aggSig));
        REQUIRE(BLS::Verify(aggSig2));
    }

    SECTION("Should aggregate same message with agg sk") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();

        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);
        BLSPublicKey pk2 = sk2.GetPublicKey();

        std::vector<BLSPrivateKey> const privateKeys = {sk1, sk2};
        std::vector<BLSPublicKey> const pubKeys = {pk1, pk2};
        const BLSPrivateKey aggSk = BLS::AggregatePrivKeys(
                privateKeys, pubKeys, true);

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message1, sizeof(message1));

        BLSSignature aggSig2 = aggSk.Sign(message1, sizeof(message1));

        std::vector<BLSSignature> const sigs = {sig1, sig2};
        std::vector<uint8_t*> const messages = {message1, message1};
        std::vector<size_t> const messageLens = {sizeof(message1), sizeof(message1)};
        BLSSignature aggSig = BLS::AggregateSigs(sigs);
        ASSERT(aggSig == aggSig2);

        const BLSPublicKey aggPubKey = BLS::AggregatePubKeys(pubKeys, true);
        REQUIRE(BLS::Verify(aggSig));
        REQUIRE(BLS::Verify(aggSig2));
    }
}

TEST_CASE("HD keys") {
    SECTION("Should create an extended private key from seed") {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));

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


    SECTION("Should match derivation through private and public keys") {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        BLSPublicKey pk1 = esk.PrivateChild(238757).GetPublicKey();
        BLSPublicKey pk2 = epk.PublicChild(238757).GetPublicKey();

        REQUIRE(pk1 == pk2);

        BLSPrivateKey sk3 = esk.PrivateChild(0)
                              .PrivateChild(3)
                              .PrivateChild(8)
                              .PrivateChild(1)
                              .GetPrivateKey();

        BLSPublicKey pk4 = epk.PublicChild(0)
                              .PublicChild(3)
                              .PublicChild(8)
                              .PublicChild(1)
                              .GetPublicKey();
        REQUIRE(sk3.GetPublicKey() == pk4);

        BLSSignature sig = sk3.Sign(seed, sizeof(seed));

        REQUIRE(BLS::Verify(sig));
    }

    SECTION("Should prevent hardened pk derivation") {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        ExtendedPrivateKey sk = esk.PrivateChild((1 << 31) + 3);
        REQUIRE_THROWS(epk.PublicChild((1 << 31) + 3));
    }

    SECTION("Should derive public child from parent") {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 0, 0, 0};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        ExtendedPublicKey pk1 = esk.PublicChild(13);
        ExtendedPublicKey pk2 = epk.PublicChild(13);

        REQUIRE(pk1 == pk2);
    }

    SECTION("Should cout structures") {
        uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 0, 0, 0};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        cout << epk << endl;
        cout << epk.GetPublicKey() << endl;
        cout << epk.GetChainCode() << endl;

        BLSSignature sig1 = esk.GetPrivateKey()
                               .Sign(seed, sizeof(seed));
        cout << sig1 << endl;
    }

    SECTION("Should serialize extended keys") {
        uint8_t seed[] = {1, 50, 6, 244, 25, 199, 1, 25};
        ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
                seed, sizeof(seed));
        ExtendedPublicKey epk = esk.GetExtendedPublicKey();

        BLSPublicKey pk1 = esk.PrivateChild(238757).GetPublicKey();
        BLSPublicKey pk2 = epk.PublicChild(238757).GetPublicKey();

        REQUIRE(pk1 == pk2);

        ExtendedPrivateKey sk3 = esk.PrivateChild(0)
                              .PrivateChild(3)
                              .PrivateChild(8)
                              .PrivateChild(1);

        ExtendedPublicKey pk4 = epk.PublicChild(0)
                              .PublicChild(3)
                              .PublicChild(8)
                              .PublicChild(1);
        uint8_t buffer1[ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE];
        uint8_t buffer2[ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];
        uint8_t buffer3[ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];

        sk3.Serialize(buffer1);
        sk3.GetExtendedPublicKey().Serialize(buffer2);
        pk4.Serialize(buffer3);
        REQUIRE(std::memcmp(buffer2, buffer3,
                ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE) == 0);
    }
}

TEST_CASE("AggregationInfo") {
    SECTION("Should create object") {
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
        BLSUtil::Hash256(messageHash1, message1, 7);
        BLSUtil::Hash256(messageHash2, message2, 8);
        BLSUtil::Hash256(messageHash3, message3, 8);
        BLSUtil::Hash256(messageHash4, message4, 8);
        BLSUtil::Hash256(messageHash5, message5, 8);
        BLSUtil::Hash256(messageHash6, message6, 8);

        uint8_t seed[32];
        getRandomSeed(seed);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        BLSPrivateKey sk4 = BLSPrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        BLSPrivateKey sk5 = BLSPrivateKey::FromSeed(seed, 32);
        getRandomSeed(seed);
        BLSPrivateKey sk6 = BLSPrivateKey::FromSeed(seed, 32);

        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPublicKey pk2 = sk2.GetPublicKey();
        BLSPublicKey pk3 = sk3.GetPublicKey();
        BLSPublicKey pk4 = sk4.GetPublicKey();
        BLSPublicKey pk5 = sk5.GetPublicKey();
        BLSPublicKey pk6 = sk6.GetPublicKey();

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

    SECTION("Should aggregate with multiple levels.") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[8] = {192, 29, 2, 0, 0, 45, 23, 192};
        uint8_t message3[7] = {52, 29, 2, 0, 0, 45, 102};
        uint8_t message4[7] = {99, 29, 2, 0, 0, 45, 222};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);

        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message2, sizeof(message2));
        BLSSignature sig3 = sk2.Sign(message1, sizeof(message1));
        BLSSignature sig4 = sk1.Sign(message3, sizeof(message3));
        BLSSignature sig5 = sk1.Sign(message4, sizeof(message4));
        BLSSignature sig6 = sk1.Sign(message1, sizeof(message1));

        std::vector<BLSSignature> const sigsL = {sig1, sig2};
        std::vector<BLSPublicKey> const pksL = {pk1, pk2};
        const BLSSignature aggSigL = BLS::AggregateSigs(sigsL);

        std::vector<BLSSignature> const sigsR = {sig3, sig4, sig6};
        const BLSSignature aggSigR = BLS::AggregateSigs(sigsR);

        std::vector<BLSPublicKey> pk1Vec = {pk1};

        std::vector<BLSSignature> sigs = {aggSigL, aggSigR, sig5};

        const BLSSignature aggSig = BLS::AggregateSigs(sigs);

        REQUIRE(BLS::Verify(aggSig));
    }

    SECTION("Should aggregate with multiple levels, degenerate") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t seed[32];
        getRandomSeed(seed);
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSSignature aggSig = sk1.Sign(message1, sizeof(message1));

        for (size_t i = 0; i < 10; i++) {
            getRandomSeed(seed);
            BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, 32);
            BLSPublicKey pk = sk.GetPublicKey();
            BLSSignature sig = sk.Sign(message1, sizeof(message1));
            std::vector<BLSSignature> sigs = {aggSig, sig};
            aggSig = BLS::AggregateSigs(sigs);
        }
        REQUIRE(BLS::Verify(aggSig));
        uint8_t sigSerialized[BLSSignature::SIGNATURE_SIZE];
        aggSig.Serialize(sigSerialized);

        const BLSSignature aggSig2 = BLSSignature::FromBytes(sigSerialized);
        REQUIRE(BLS::Verify(aggSig2) == false);
    }

    SECTION("Should aggregate with multiple levels, different messages") {
        uint8_t message1[7] = {100, 2, 254, 88, 90, 45, 23};
        uint8_t message2[7] = {192, 29, 2, 0, 0, 45, 23};
        uint8_t message3[7] = {52, 29, 2, 0, 0, 45, 102};
        uint8_t message4[7] = {99, 29, 2, 0, 0, 45, 222};

        uint8_t seed[32];
        getRandomSeed(seed);
        uint8_t seed2[32];
        getRandomSeed(seed2);

        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, 32);
        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed2, 32);

        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSPublicKey pk2 = sk2.GetPublicKey();

        BLSSignature sig1 = sk1.Sign(message1, sizeof(message1));
        BLSSignature sig2 = sk2.Sign(message2, sizeof(message2));
        BLSSignature sig3 = sk2.Sign(message3, sizeof(message4));
        BLSSignature sig4 = sk1.Sign(message4, sizeof(message4));

        std::vector<BLSSignature> const sigsL = {sig1, sig2};
        std::vector<BLSPublicKey> const pksL = {pk1, pk2};
        std::vector<uint8_t*> const messagesL = {message1, message2};
        std::vector<size_t> const messageLensL = {sizeof(message1),
                                             sizeof(message2)};
        const BLSSignature aggSigL = BLS::AggregateSigs(sigsL);

        std::vector<BLSSignature> const sigsR = {sig3, sig4};
        std::vector<BLSPublicKey> const pksR = {pk2, pk1};
        std::vector<uint8_t*> const messagesR = {message3, message4};
        std::vector<size_t> const messageLensR = {sizeof(message3),
                                             sizeof(message4)};
        const BLSSignature aggSigR = BLS::AggregateSigs(sigsR);

        std::vector<BLSSignature> sigs = {aggSigL, aggSigR};
        std::vector<std::vector<BLSPublicKey> > pks = {pksL, pksR};
        std::vector<std::vector<uint8_t*> > messages = {messagesL, messagesR};
        std::vector<std::vector<size_t> > messageLens = {messageLensL, messageLensR};

        const BLSSignature aggSig = BLS::AggregateSigs(sigs);

        std::vector<BLSPublicKey> allPks = {pk1, pk2, pk2, pk1};
        std::vector<uint8_t*> allMessages = {message1, message2,
                                              message3, message4};
        std::vector<size_t> allMessageLens = {sizeof(message1), sizeof(message2),
                                         sizeof(message3), sizeof(message4)};

        REQUIRE(BLS::Verify(aggSig));
    }
    SECTION("README") {
        // Example seed, used to generate private key. Always use
        // a secure RNG with sufficient entropy to generate a seed.
        uint8_t seed[] = {0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                        19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                        82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22};

        BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, sizeof(seed));
        BLSPublicKey pk = sk.GetPublicKey();

        uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};

        BLSSignature sig = sk.Sign(msg, sizeof(msg));

        uint8_t skBytes[BLSPrivateKey::PRIVATE_KEY_SIZE];  // 32 byte array
        uint8_t pkBytes[BLSPublicKey::PUBLIC_KEY_SIZE];    // 48 byte array
        uint8_t sigBytes[BLSSignature::SIGNATURE_SIZE];    // 96 byte array

        sk.Serialize(skBytes);   // 32 bytes
        pk.Serialize(pkBytes);   // 48 bytes
        sig.Serialize(sigBytes); // 96 bytes
        // Takes array of 32 bytes
        sk = BLSPrivateKey::FromBytes(skBytes);

        // Takes array of 48 bytes
        pk = BLSPublicKey::FromBytes(pkBytes);

        // Takes array of 96 bytes
        sig = BLSSignature::FromBytes(sigBytes);
        // Add information required for verification, to sig object
        sig.SetAggregationInfo(AggregationInfo::FromMsg(pk, msg, sizeof(msg)));

        bool ok = BLS::Verify(sig);
        // Generate some more private keys
        seed[0] = 1;
        BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, sizeof(seed));
        seed[0] = 2;
        BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed, sizeof(seed));

        // Generate first sig
        BLSPublicKey pk1 = sk1.GetPublicKey();
        BLSSignature sig1 = sk1.Sign(msg, sizeof(msg));

        // Generate second sig
        BLSPublicKey pk2 = sk2.GetPublicKey();
        BLSSignature sig2 = sk2.Sign(msg, sizeof(msg));

        // Aggregate signatures together
        std::vector<BLSSignature> sigs = {sig1, sig2};
        BLSSignature aggSig = BLS::AggregateSigs(sigs);

        // For same message, public keys can be aggregated into one.
        // The signature can be verified the same as a single signature,
        // using this public key.
        std::vector<BLSPublicKey> pubKeys = {pk1, pk2};
        BLSPublicKey aggPubKey = BLS::AggregatePubKeys(pubKeys, true);
        // Generate one more key
        seed[0] = 3;
        BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed, sizeof(seed));
        BLSPublicKey pk3 = sk3.GetPublicKey();
        uint8_t msg2[] = {100, 2, 254, 88, 90, 45, 23};

        // Generate the signatures, assuming we have 3 private keys
        sig1 = sk1.Sign(msg, sizeof(msg));
        sig2 = sk2.Sign(msg, sizeof(msg));
        BLSSignature sig3 = sk3.Sign(msg2, sizeof(msg2));

        // They can be noninteractively combined by anyone
        // Aggregation below can also be done by the verifier, to
        // make batch verification more efficient
        std::vector<BLSSignature> sigsL = {sig1, sig2};
        BLSSignature aggSigL = BLS::AggregateSigs(sigsL);

        // Arbitrary trees of aggregates
        std::vector<BLSSignature> sigsFinal = {aggSigL, sig3};
        BLSSignature aggSigFinal = BLS::AggregateSigs(sigsFinal);

        // Serialize the final signature
        aggSigFinal.Serialize(sigBytes);
        // Deserialize aggregate signature
        aggSigFinal = BLSSignature::FromBytes(sigBytes);

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
        ok = BLS::Verify(aggSigFinal);

        // If you previously verified a signature, you can also divide
        // the aggregate signature by the signature you already verified.
        ok = BLS::Verify(aggSigL);
        std::vector<BLSSignature> cache = {aggSigL};
        aggSigFinal = aggSigFinal.DivideBy(cache);

        // Final verification is now more efficient
        ok = BLS::Verify(aggSigFinal);

        std::vector<BLSPrivateKey> privateKeysList = {sk1, sk2};
        std::vector<BLSPublicKey> pubKeysList = {pk1, pk2};

        // Create an aggregate private key, that can generate
        // aggregate signatures
        const BLSPrivateKey aggSk = BLS::AggregatePrivKeys(
                privateKeysList, pubKeysList, true);

        BLSSignature aggSig3 = aggSk.Sign(msg, sizeof(msg));
    }
}

int main(int argc, char* argv[]) {
    int result = Catch::Session().run(argc, argv);
    return result;
}
