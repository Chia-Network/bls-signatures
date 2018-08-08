#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/operators.h>

#include "../src/blsprivatekey.hpp"
#include "../src/bls.hpp"

namespace py = pybind11;

PYBIND11_MODULE(blspy, m) {
    py::class_<relic::bn_t*>(m, "bn_ptr");

    py::class_<AggregationInfo>(m, "AggregationInfo")
        .def("from_msg_hash", [](const BLSPublicKey &pk, const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return AggregationInfo::FromMsgHash(pk, input);
        })
        .def("from_msg", [](const BLSPublicKey &pk, const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return AggregationInfo::FromMsg(pk, input, len(b));
        })
        .def("merge_infos", &AggregationInfo::MergeInfos)
        .def("get_pubkeys", &AggregationInfo::GetPubKeys)
        .def("get_msg_hashes", [](const AggregationInfo &self) {
            vector<uint8_t*> msgHashes = self.GetMessageHashes();
            vector<py::bytes> ret;
            for (const uint8_t* msgHash : msgHashes) {
                ret.push_back(py::bytes(reinterpret_cast<const char*>(msgHash), BLS::MESSAGE_HASH_LEN));
            }
            return ret;
        })
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self < py::self)
        .def("__repr__", [](const AggregationInfo &a) {
            std::stringstream s;
            s << a;
            return "<AggregationInfo " + s.str() + ">";
        });

    py::class_<BLSPrivateKey>(m, "BLSPrivateKey")
        .def_property_readonly_static("PRIVATE_KEY_SIZE", [](py::object self) {
            return BLSPrivateKey::PRIVATE_KEY_SIZE;
        })
        .def("from_seed", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return BLSPrivateKey::FromSeed(input, len(b));
        })
        .def("from_bytes", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return BLSPrivateKey::FromBytes(input);
        })
        .def("serialize", [](const BLSPrivateKey &k) {
            uint8_t* output = BLSUtil::SecAlloc<uint8_t>(BLSPrivateKey::PRIVATE_KEY_SIZE);
            k.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), BLSPrivateKey::PRIVATE_KEY_SIZE);
            BLSUtil::SecFree(output);
            return ret;
        })
        .def("get_public_key", [](const BLSPrivateKey &k) {
            return k.GetPublicKey();
        })
        .def("sign", [](const BLSPrivateKey &k, const py::bytes &msg) {
            uint8_t* input = reinterpret_cast<uint8_t*>(&std::string(msg)[0]);
            return k.Sign(input, len(msg));
        })
        .def("sign_prehashed", [](const BLSPrivateKey &k, const py::bytes &msg) {
            uint8_t* input = reinterpret_cast<uint8_t*>(&std::string(msg)[0]);
            return k.SignPrehashed(input);
        })
        .def("size", &BLSPrivateKey::size)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const BLSPrivateKey &k) {
            uint8_t* output = BLSUtil::SecAlloc<uint8_t>(BLSPrivateKey::PRIVATE_KEY_SIZE);
            k.Serialize(output);
            std::string ret = "<BLSPrivateKey " + BLSUtil::HexStr(output, BLSPrivateKey::PRIVATE_KEY_SIZE) + ">";
            BLSUtil::SecFree(output);
            return ret;
        });


    py::class_<BLSPublicKey>(m, "BLSPublicKey")
        .def_property_readonly_static("PUBLIC_KEY_SIZE", [](py::object self) {
            return BLSPublicKey::PUBLIC_KEY_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return BLSPublicKey::FromBytes(input);
        })
        .def("get_fingerprint", &BLSPublicKey::GetFingerprint)
        .def("serialize", [](const BLSPublicKey &pk) {
            uint8_t* output = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
            pk.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), BLSPublicKey::PUBLIC_KEY_SIZE);
            delete[] output;
            return ret;
        })
        .def("size", &BLSPublicKey::size)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self < py::self)
        .def("__repr__", [](const BLSPublicKey &pk) {
            std::stringstream s;
            s << pk;
            return "<BLSPublicKey " + s.str() + ">";
        });


    py::class_<BLSSignature>(m, "BLSSignature")
        .def_property_readonly_static("SIGNATURE_SIZE", [](py::object self) {
            return BLSSignature::SIGNATURE_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return BLSSignature::FromBytes(input);
        })
        .def("serialize", [](const BLSSignature &sig) {
            uint8_t* output = new uint8_t[BLSSignature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), BLSSignature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("divide_by", &BLSSignature::DivideBy)
        .def("set_aggregation_info", &BLSSignature::SetAggregationInfo)
        .def("get_aggregation_info", [](const BLSSignature &sig) {
            return *sig.GetAggregationInfo();
        })
        .def("size", &BLSSignature::size)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self < py::self)
        .def("__repr__", [](const BLSSignature &sig) {
            std::stringstream s;
            s << sig;
            return "<BLSSignature " + s.str() + ">";
        });

    py::class_<ChainCode>(m, "ChainCode")
        .def_property_readonly_static("CHAIN_CODE_KEY_SIZE", [](py::object self) {
            return ChainCode::CHAIN_CODE_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return ChainCode::FromBytes(input);
        })
        .def("serialize", [](const ChainCode &cc) {
            uint8_t* output = new uint8_t[ChainCode::CHAIN_CODE_SIZE];
            cc.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output),
                    ChainCode::CHAIN_CODE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__repr__", [](const ChainCode &cc) {
            uint8_t* output = new uint8_t[ChainCode::CHAIN_CODE_SIZE];
            cc.Serialize(output);
            std::string ret = "<ChainCode " + BLSUtil::HexStr(output,
                    ChainCode::CHAIN_CODE_SIZE) + ">";
            BLSUtil::SecFree(output);
            return ret;
        });



    py::class_<ExtendedPublicKey>(m, "ExtendedPublicKey")
        .def_property_readonly_static("EXTENDED_PUBLIC_KEY_SIZE", [](py::object self) {
            return ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return ExtendedPublicKey::FromBytes(input);
        })
        .def("public_child", &ExtendedPublicKey::PublicChild)
        .def("get_version", &ExtendedPublicKey::GetVersion)
        .def("get_depth", &ExtendedPublicKey::GetDepth)
        .def("get_parent_fingerprint", &ExtendedPublicKey::GetParentFingerprint)
        .def("get_child_number", &ExtendedPublicKey::GetChildNumber)
        .def("get_chain_code", &ExtendedPublicKey::GetChainCode)
        .def("get_public_key", &ExtendedPublicKey::GetPublicKey)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("serialize", [](const ExtendedPublicKey &pk) {
            uint8_t* output = new uint8_t[
                    ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];
            pk.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output),
                    ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE);
            delete[] output;
            return ret;
        })
        .def("__repr__", [](const ExtendedPublicKey &pk) {
            uint8_t* output = new uint8_t[
                    ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];
            pk.Serialize(output);
            std::string ret = "<ExtendedPublicKey " + BLSUtil::HexStr(output,
                    ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE) + ">";
            BLSUtil::SecFree(output);
            return ret;
        });

    py::class_<ExtendedPrivateKey>(m, "ExtendedPrivateKey")
        .def_property_readonly_static("EXTENDED_PRIVATE_KEY_SIZE", [](py::object self) {
            return ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE;
        })
        .def("from_seed", [](const py::bytes &seed) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(seed)[0]);
            return ExtendedPrivateKey::FromSeed(input, len(seed));
        })
        .def("from_bytes", [](const py::bytes &b) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(b)[0]);
            return ExtendedPrivateKey::FromBytes(input);
        })
        .def("private_child", &ExtendedPrivateKey::PrivateChild)
        .def("public_child", &ExtendedPrivateKey::PublicChild)
        .def("get_version", &ExtendedPrivateKey::GetVersion)
        .def("get_depth", &ExtendedPrivateKey::GetDepth)
        .def("get_parent_fingerprint", &ExtendedPrivateKey::GetParentFingerprint)
        .def("get_child_number", &ExtendedPrivateKey::GetChildNumber)
        .def("get_chain_code", &ExtendedPrivateKey::GetChainCode)
        .def("get_private_key", &ExtendedPrivateKey::GetPrivateKey)
        .def("get_public_key", &ExtendedPrivateKey::GetPublicKey)
        .def("get_extended_public_key", &ExtendedPrivateKey::GetExtendedPublicKey)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("serialize", [](const ExtendedPrivateKey &k) {
            uint8_t* output = BLSUtil::SecAlloc<uint8_t>(
                    ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE);
            k.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output),
                    ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE);
            BLSUtil::SecFree(output);
            return ret;
        })
        .def("__repr__", [](const ExtendedPrivateKey &k) {
            uint8_t* output = BLSUtil::SecAlloc<uint8_t>(
                    ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE);
            k.Serialize(output);
            std::string ret = "<ExtendedPrivateKey " + BLSUtil::HexStr(output,
                    ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE) + ">";
            BLSUtil::SecFree(output);
            return ret;
        });


    py::class_<BLS>(m, "BLS")
        .def_property_readonly_static("MESSAGE_HASH_LEN", [](py::object self) {
            return BLS::MESSAGE_HASH_LEN;
        })
        .def("init", &BLS::Init)
        .def("assert_initialized", &BLS::AssertInitialized)
        .def("clean", &BLS::Clean)
        .def("aggregate_sigs", &BLS::AggregateSigs)
        .def("verify", &BLS::Verify)
        .def("aggregate_pub_keys", &BLS::AggregatePubKeys)
        .def("aggregate_priv_keys", &BLS::AggregatePrivKeys);

    py::class_<BLSUtil>(m, "BLSUtil")
        .def("hash256", [](const py::bytes &message) {
            const uint8_t* input = reinterpret_cast<const uint8_t*>(&std::string(message)[0]);
            uint8_t output[BLS::MESSAGE_HASH_LEN];
            BLSUtil::Hash256(output, input, len(message));
            return py::bytes(reinterpret_cast<char*>(output), BLS::MESSAGE_HASH_LEN);
        });

#ifdef VERSION_INFO
    m.attr("__version__") = VERSION_INFO;
#else
    m.attr("__version__") = "dev";
#endif
}