// Copyright 2020 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../src/bls.hpp"
#include "../src/elements.hpp"
#include "../src/hdkeys.hpp"
#include "../src/privatekey.hpp"
#include "../src/schemes.hpp"

namespace py = pybind11;
using namespace bls;
using std::vector;

template <typename... Args>
using overload_cast_ = pybind11::detail::overload_cast_impl<Args...>;

PYBIND11_MODULE(blspy, m)
{
    py::class_<BNWrapper>(m, "BNWrapper")
        .def(py::init(&BNWrapper::FromByteVector))
        .def(py::init([](py::int_ pyint) {
            size_t n_bytes = 1 + ((_PyLong_NumBits(pyint.ptr()) + 7) / 8);
            std::vector<uint8_t> buffer(n_bytes, 0);
            if (_PyLong_AsByteArray(
                    (PyLongObject *)pyint.ptr(), buffer.data(), n_bytes, 0, 0) <
                0) {
                throw std::invalid_argument("Failed to cast int to BNWrapper");
            }
            return BNWrapper::FromByteVector(buffer);
        }))
        .def(
            "__repr__",
            [](const BNWrapper &b) {
                std::stringstream s;
                s << b;
                return "<BNWrapper " + s.str() + ">";
            })
        .def(
            "__deepcopy__",
            [](const BNWrapper &k, const py::object &memo) {
                return BNWrapper(k);
            })
        .def(
            "__str__",
            [](const BNWrapper &b) {
                std::stringstream s;
                s << b;
                return s.str();
            })
        .def("__bytes__", [](const BNWrapper &b) {
            std::stringstream s;
            int length = bn_size_bin(*b.b);
            uint8_t *out = new uint8_t[length];
            bn_write_bin(out, length, *b.b);
            s << out;
            delete[] out;
            return py::bytes(s.str());
        });

    py::implicitly_convertible<py::int_, BNWrapper>();

    py::class_<PrivateKey>(m, "PrivateKey")
        .def_property_readonly_static(
            "PRIVATE_KEY_SIZE",
            [](py::object self) { return PrivateKey::PRIVATE_KEY_SIZE; })
        .def(
            "from_bytes",
            [](py::buffer const b) {
                py::buffer_info info = b.request();
                if (info.format != py::format_descriptor<uint8_t>::format() ||
                    info.ndim != 1)
                    throw std::runtime_error("Incompatible buffer format!");

                if ((int)info.size != PrivateKey::PRIVATE_KEY_SIZE) {
                    throw std::invalid_argument(
                        "Length of bytes object not equal to PrivateKey::SIZE");
                }
                auto data_ptr = reinterpret_cast<const uint8_t *>(info.ptr);
                return PrivateKey::FromBytes(data_ptr);
            })
        .def(
            "__bytes__",
            [](const PrivateKey &k) {
                uint8_t *output =
                    Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
                k.Serialize(output);
                py::bytes ret = py::bytes(
                    reinterpret_cast<char *>(output),
                    PrivateKey::PRIVATE_KEY_SIZE);
                Util::SecFree(output);
                return ret;
            })
        .def(
            "__deepcopy__",
            [](const PrivateKey &k, const py::object &memo) {
                return PrivateKey(k);
            })
        .def("get_g1", [](const PrivateKey &k) { return k.GetG1Element(); })
        .def("aggregate", &PrivateKey::Aggregate)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const PrivateKey &k) {
            uint8_t *output =
                Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
            k.Serialize(output);
            std::string ret =
                "<PrivateKey " +
                Util::HexStr(output, PrivateKey::PRIVATE_KEY_SIZE) + ">";
            Util::SecFree(output);
            return ret;
        });

    py::class_<Util>(m, "Util").def("hash256", [](const py::bytes &message) {
        std::string str(message);
        const uint8_t *input = reinterpret_cast<const uint8_t *>(str.data());
        uint8_t output[BLS::MESSAGE_HASH_LEN];
        Util::Hash256(output, (const uint8_t *)str.data(), str.size());
        return py::bytes(
            reinterpret_cast<char *>(output), BLS::MESSAGE_HASH_LEN);
    });

    py::class_<BasicSchemeMPL>(m, "BasicSchemeMPL")
        .def("sk_to_g1", &BasicSchemeMPL::SkToG1)
        .def(
            "key_gen",
            [](const py::bytes &b) {
                std::string str(b);
                const uint8_t *input =
                    reinterpret_cast<const uint8_t *>(str.data());
                const vector<uint8_t> inputVec(input, input + len(b));
                return BasicSchemeMPL::KeyGen(inputVec);
            })
        .def("derive_child_sk", &BasicSchemeMPL::DeriveChildSk)
        .def("derive_child_sk_unhardened", &BasicSchemeMPL::DeriveChildSkUnhardened)
        .def("derive_child_pk_unhardened", &BasicSchemeMPL::DeriveChildPkUnhardened)
        .def(
            "aggregate",
            overload_cast_<const vector<G2Element> &>()(
                &BasicSchemeMPL::Aggregate))
        .def(
            "sign",
            [](const PrivateKey &pk, const py::bytes &msg) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return BasicSchemeMPL::Sign(pk, v);
            })
        .def(
            "verify",
            [](const G1Element &pk,
               const py::bytes &msg,
               const G2Element &sig) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return BasicSchemeMPL::Verify(pk, v, sig);
            })
        .def(
            "aggregate_verify",
            [](const vector<G1Element> &pks,
               const vector<py::bytes> &msgs,
               const G2Element &sig) {
                vector<vector<uint8_t>> vecs(msgs.size());
                for (int i = 0; i < (int)msgs.size(); ++i) {
                    std::string s(msgs[i]);
                    vecs[i] = vector<uint8_t>(s.begin(), s.end());
                }

                return BasicSchemeMPL::AggregateVerify(pks, vecs, sig);
            });

    py::class_<AugSchemeMPL>(m, "AugSchemeMPL")
        .def("sk_to_g1", &AugSchemeMPL::SkToG1)
        .def(
            "key_gen",
            [](const py::bytes &b) {
                std::string str(b);
                const uint8_t *input =
                    reinterpret_cast<const uint8_t *>(str.data());
                const vector<uint8_t> inputVec(input, input + len(b));
                return AugSchemeMPL::KeyGen(inputVec);
            })
        .def("derive_child_sk", &AugSchemeMPL::DeriveChildSk)
        .def("derive_child_sk_unhardened", &AugSchemeMPL::DeriveChildSkUnhardened)
        .def("derive_child_pk_unhardened", &AugSchemeMPL::DeriveChildPkUnhardened)
        .def(
            "aggregate",
            overload_cast_<const vector<G2Element> &>()(
                &AugSchemeMPL::Aggregate))
        .def(
            "sign",
            [](const PrivateKey &pk, const py::bytes &msg) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return AugSchemeMPL::Sign(pk, v);
            })
        .def(
            "sign",
            [](const PrivateKey &pk,
               const py::bytes &msg,
               const G1Element &prepend_pk) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return AugSchemeMPL::Sign(pk, v, prepend_pk);
            })
        .def(
            "verify",
            [](const G1Element &pk,
               const py::bytes &msg,
               const G2Element &sig) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return AugSchemeMPL::Verify(pk, v, sig);
            })
        .def(
            "aggregate_verify",
            [](const vector<G1Element> &pks,
               const vector<py::bytes> &msgs,
               const G2Element &sig) {
                vector<vector<uint8_t>> vecs(msgs.size());
                for (int i = 0; i < (int)msgs.size(); ++i) {
                    std::string s(msgs[i]);
                    vecs[i] = vector<uint8_t>(s.begin(), s.end());
                }

                return AugSchemeMPL::AggregateVerify(pks, vecs, sig);
            });

    py::class_<PopSchemeMPL>(m, "PopSchemeMPL")
        .def("sk_to_g1", &PopSchemeMPL::SkToG1)
        .def(
            "key_gen",
            [](const py::bytes &b) {
                std::string str(b);
                const uint8_t *input =
                    reinterpret_cast<const uint8_t *>(str.data());
                const vector<uint8_t> inputVec(input, input + len(b));
                return PopSchemeMPL::KeyGen(inputVec);
            })
        .def("derive_child_sk", &PopSchemeMPL::DeriveChildSk)
        .def("derive_child_sk_unhardened", &PopSchemeMPL::DeriveChildSkUnhardened)
        .def("derive_child_pk_unhardened", &PopSchemeMPL::DeriveChildPkUnhardened)
        .def(
            "aggregate",
            overload_cast_<const vector<vector<uint8_t>> &>()(
                &PopSchemeMPL::Aggregate))
        .def(
            "aggregate",
            overload_cast_<const vector<G2Element> &>()(
                &PopSchemeMPL::Aggregate))
        .def(
            "sign",
            [](const PrivateKey &pk, const py::bytes &msg) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return PopSchemeMPL::Sign(pk, v);
            })
        .def(
            "verify",
            [](const G1Element &pk,
               const py::bytes &msg,
               const G2Element &sig) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return PopSchemeMPL::Verify(pk, v, sig);
            })
        .def(
            "aggregate_verify",
            [](const vector<G1Element> &pks,
               const vector<py::bytes> &msgs,
               const G2Element &sig) {
                vector<vector<uint8_t>> vecs(msgs.size());
                for (int i = 0; i < (int)msgs.size(); ++i) {
                    std::string s(msgs[i]);
                    vecs[i] = vector<uint8_t>(s.begin(), s.end());
                }

                return PopSchemeMPL::AggregateVerify(pks, vecs, sig);
            })
        .def("pop_prove", &PopSchemeMPL::PopProve)
        .def(
            "pop_verify",
            overload_cast_<const G1Element &, const G2Element &>()(
                &PopSchemeMPL::PopVerify))
        .def(
            "fast_aggregate_verify",
            overload_cast_<
                const vector<G1Element> &,
                const vector<uint8_t> &,
                const G2Element &>()(&PopSchemeMPL::FastAggregateVerify))
        .def(
            "fast_aggregate_verify",
            [](const vector<G1Element> &pks,
               const py::bytes &msg,
               const G2Element &sig) {
                std::string s(msg);
                vector<uint8_t> v(s.begin(), s.end());
                return PopSchemeMPL::FastAggregateVerify(pks, v, sig);
            });

    py::class_<G1Element>(m, "G1Element")
        .def_property_readonly_static(
            "SIZE", [](py::object self) { return G1Element::SIZE; })
        .def(py::init(&G1Element::FromByteVector))
        .def(py::init([](py::int_ pyint) {
            std::vector<uint8_t> buffer(G1Element::SIZE, 0);
            if (_PyLong_AsByteArray(
                    (PyLongObject *)pyint.ptr(),
                    buffer.data(),
                    G1Element::SIZE,
                    0,
                    0) < 0) {
                throw std::invalid_argument("Failed to cast int to G1Element");
            }
            return G1Element::FromByteVector(buffer);
        }))
        .def(py::init([](py::buffer const b) {
            py::buffer_info info = b.request();
            if (info.format != py::format_descriptor<uint8_t>::format() ||
                info.ndim != 1)
                throw std::runtime_error("Incompatible buffer format!");

            if ((int)info.size != G1Element::SIZE) {
                throw std::invalid_argument(
                    "Length of bytes object not equal to G1Element::SIZE");
            }
            auto data_ptr = static_cast<uint8_t *>(info.ptr);
            std::vector<uint8_t> data(data_ptr, data_ptr + info.size);
            return G1Element::FromByteVector(data);
        }))
        .def(
            "from_bytes",
            [](py::buffer const b) {
                py::buffer_info info = b.request();
                if (info.format != py::format_descriptor<uint8_t>::format() ||
                    info.ndim != 1)
                    throw std::runtime_error("Incompatible buffer format!");

                if ((int)info.size != G1Element::SIZE) {
                    throw std::invalid_argument(
                        "Length of bytes object not equal to G1Element::SIZE");
                }
                auto data_ptr = reinterpret_cast<const uint8_t *>(info.ptr);
                return G1Element::FromBytes(data_ptr);
            })
        .def("generator", &G1Element::Generator)
        .def("from_message", &G1Element::FromMessage)
        .def("pair", &G1Element::Pair)
        .def("negate", &G1Element::Negate)
        .def("infinity", &G1Element::Infinity)
        .def("get_fingerprint", &G1Element::GetFingerprint)

        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(
            "__deepcopy__",
            [](const G1Element &g1, const py::object &memo) {
                return G1Element(g1);
            })
        .def(
            "__add__",
            [](G1Element &self, G1Element &other) { return self + other; },
            py::is_operator())
        .def(
            "__mul__",
            [](G1Element &self, bn_t other) {
                return self * (*(bn_t *)&other);
            },
            py::is_operator())
        .def(
            "__mul__",
            [](G1Element &self, BNWrapper other) { return self * (*other.b); },
            py::is_operator())
        .def(
            "__rmul__",
            [](G1Element &self, bn_t other) {
                return self * (*(bn_t *)&other);
            },
            py::is_operator())
        .def(
            "__rmul__",
            [](G1Element &self, BNWrapper other) { return self * (*other.b); },
            py::is_operator())
        .def(
            "__and__",
            [](G1Element &self, G2Element &other) { return self & other; },
            py::is_operator())
        .def(
            "__repr__",
            [](const G1Element &ele) {
                std::stringstream s;
                s << ele;
                return "<G1Element " + s.str() + ">";
            })
        .def(
            "__str__",
            [](const G1Element &ele) {
                std::stringstream s;
                s << ele;
                return s.str();
            })
        .def(
            "__bytes__",
            [](const G1Element &ele) {
                vector<uint8_t> out = ele.Serialize();
                py::bytes ans = py::bytes(
                    reinterpret_cast<const char *>(out.data()), G1Element::SIZE);
                return ans;
            })
        .def("__deepcopy__", [](const G1Element &ele, const py::object &memo) {
            return G1Element(ele);
        });

    py::class_<G2Element>(m, "G2Element")
        .def_property_readonly_static(
            "SIZE", [](py::object self) { return G2Element::SIZE; })
        .def(py::init(&G2Element::FromByteVector))
        .def(py::init([](py::buffer const b) {
            py::buffer_info info = b.request();
            if (info.format != py::format_descriptor<uint8_t>::format() ||
                info.ndim != 1)
                throw std::runtime_error("Incompatible buffer format!");

            if ((int)info.size != G2Element::SIZE) {
                throw std::invalid_argument(
                    "Length of bytes object not equal to G2Element::SIZE");
            }
            auto data_ptr = static_cast<uint8_t *>(info.ptr);
            std::vector<uint8_t> data(data_ptr, data_ptr + info.size);
            return G2Element::FromByteVector(data);
        }))
        .def(py::init([](py::int_ pyint) {
            std::vector<uint8_t> buffer(G2Element::SIZE, 0);
            if (_PyLong_AsByteArray(
                    (PyLongObject *)pyint.ptr(),
                    buffer.data(),
                    G2Element::SIZE,
                    0,
                    0) < 0) {
                throw std::invalid_argument("Failed to cast int to G2Element");
            }
            return G2Element::FromByteVector(buffer);
        }))
        .def(
            "from_bytes",
            [](py::buffer const b) {
                py::buffer_info info = b.request();
                if (info.format != py::format_descriptor<uint8_t>::format() ||
                    info.ndim != 1)
                    throw std::runtime_error("Incompatible buffer format!");

                if ((int)info.size != G2Element::SIZE) {
                    throw std::invalid_argument(
                        "Length of bytes object not equal to G2Element::SIZE");
                }
                auto data_ptr = reinterpret_cast<const uint8_t *>(info.ptr);
                return G2Element::FromBytes(data_ptr);
            })
        .def("generator", &G2Element::Generator)
        .def("from_message", &G2Element::FromMessage)
        .def("pair", &G2Element::Pair)
        .def("negate", &G2Element::Negate)
        .def("infinity", &G2Element::Infinity)
        .def(
            "__deepcopy__",
            [](const G2Element &g2, const py::object &memo) {
                return G2Element(g2);
            })
        .def(py::self == py::self)
        .def(py::self != py::self)

        .def(
            "__add__",
            [](G2Element &self, G2Element &other) { return self + other; },
            py::is_operator())
        .def(
            "__mul__",
            [](G2Element &self, bn_t other) {
                return self * (*(bn_t *)&other);
            },
            py::is_operator())
        .def(
            "__mul__",
            [](G2Element &self, BNWrapper other) { return self * (*other.b); },
            py::is_operator())
        .def(
            "__rmul__",
            [](G2Element &self, bn_t other) {
                return self * (*(bn_t *)&other);
            },
            py::is_operator())
        .def(
            "__rmul__",
            [](G2Element &self, BNWrapper other) { return self * (*other.b); },
            py::is_operator())

        .def(
            "__repr__",
            [](const G2Element &ele) {
                std::stringstream s;
                s << ele;
                return "<G2Element " + s.str() + ">";
            })
        .def(
            "__str__",
            [](const G2Element &ele) {
                std::stringstream s;
                s << ele;
                return s.str();
            })
        .def(
            "__bytes__",
            [](const G2Element &ele) {
                vector<uint8_t> out = ele.Serialize();
                py::bytes ans = py::bytes(
                    reinterpret_cast<const char *>(out.data()), G2Element::SIZE);
                return ans;
            })
        .def("__deepcopy__", [](const G2Element &ele, const py::object &memo) {
            return G2Element(ele);
        });

    py::class_<GTElement>(m, "GTElement")
        .def_property_readonly_static(
            "SIZE", [](py::object self) { return GTElement::SIZE; })
        .def(py::init(&GTElement::FromByteVector))
        .def(py::init([](py::buffer const b) {
            py::buffer_info info = b.request();
            if (info.format != py::format_descriptor<uint8_t>::format() ||
                info.ndim != 1)
                throw std::runtime_error("Incompatible buffer format!");

            if ((int)info.size != GTElement::SIZE) {
                throw std::invalid_argument(
                    "Length of bytes object not equal to G2Element::SIZE");
            }
            auto data_ptr = static_cast<uint8_t *>(info.ptr);
            std::vector<uint8_t> data(data_ptr, data_ptr + info.size);
            return GTElement::FromByteVector(data);
        }))
        .def(py::init([](py::int_ pyint) {
            std::vector<uint8_t> buffer(GTElement::SIZE, 0);
            if (_PyLong_AsByteArray(
                    (PyLongObject *)pyint.ptr(),
                    buffer.data(),
                    GTElement::SIZE,
                    0,
                    0) < 0) {
                throw std::invalid_argument("Failed to cast int to GTElement");
            }
            return GTElement::FromByteVector(buffer);
        }))
        .def(
            "from_bytes",
            [](py::buffer const b) {
                py::buffer_info info = b.request();
                if (info.format != py::format_descriptor<uint8_t>::format() ||
                    info.ndim != 1)
                    throw std::runtime_error("Incompatible buffer format!");

                if ((int)info.size != GTElement::SIZE) {
                    throw std::invalid_argument(
                        "Length of bytes object not equal to GTElement::SIZE");
                }
                auto data_ptr = reinterpret_cast<const uint8_t *>(info.ptr);
                return GTElement::FromBytes(data_ptr);
            })
        .def("unity", &GTElement::Unity)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(
            "__deepcopy__",
            [](const GTElement &gt, const py::object &memo) {
                return GTElement(gt);
            })
        .def(
            "__repr__",
            [](const GTElement &ele) {
                std::stringstream s;
                s << ele;
                return "<GTElement " + s.str() + ">";
            })
        .def(
            "__str__",
            [](const GTElement &ele) {
                std::stringstream s;
                s << ele;
                return s.str();
            })
        .def(
            "__bytes__",
            [](const GTElement &ele) {
                uint8_t *out = new uint8_t[GTElement::SIZE];
                ele.Serialize(out);
                py::bytes ans =
                    py::bytes(reinterpret_cast<char *>(out), GTElement::SIZE);
                delete[] out;
                return ans;
            })
        .def("__deepcopy__", [](const GTElement &ele, const py::object &memo) {
            return GTElement(ele);
        });

    m.attr("PublicKeyMPL") = m.attr("G1Element");
    m.attr("SignatureMPL") = m.attr("G2Element");

#ifdef VERSION_INFO
    m.attr("__version__") = VERSION_INFO;
#else
    m.attr("__version__") = "dev";
#endif
}
