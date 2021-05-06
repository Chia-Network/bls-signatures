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

#ifndef JS_BINDINGS_WRAPPERS_SCHEMEMPLWRAPPER_H_
#define JS_BINDINGS_WRAPPERS_SCHEMEMPLWRAPPER_H_

#include "../helpers.h"
#include "JSWrapper.h"
#include "G1ElementWrapper.h"
#include "PrivateKeyWrapper.h"

namespace js_wrappers {

// Basic scheme wrapper providing most of the methods.
template <typename SchemeMPL> class SchemeMPLWrapper : public JSWrapper<SchemeMPL> {
 public:
  static G1ElementWrapper SkToG1(const PrivateKeyWrapper &seckey) {
    auto mpl = SchemeMPL();
    return G1ElementWrapper(mpl.SkToG1(seckey.GetWrappedInstance()));
  }

  static PrivateKeyWrapper KeyGen(val seedVal) {
    auto mpl = SchemeMPL();
    std::vector <uint8_t> seed = helpers::toVector(seedVal);
    return PrivateKeyWrapper(mpl.KeyGen(seed));
  }
};

}  // namespace js_wrappers

#endif  // JS_BINDINGS_WRAPPERS_SIGNATUREWRAPPER_H_
