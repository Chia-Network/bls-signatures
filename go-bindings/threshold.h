// Copyright 2019 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GO_BINDINGS_THRESHOLD_H_
#define GO_BINDINGS_THRESHOLD_H_
#include <stdbool.h>
#include "privatekey.h"
#include "signature.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef void* CBigNum;

CPrivateKey CThresholdCreate(void **commitments, void **secretFragments,
    size_t T, size_t N);

void** CThresholdLagrangeCoeffsAtZero(size_t *players, size_t T);

void* CThresholdInterpolateAtZero(size_t *X, CBigNum *Y, size_t T);

bool CThresholdVerifySecretFragment(size_t player, CPrivateKey secretFragment,
    void **commitments, size_t numCommitments, size_t T);

CInsecureSignature CThresholdSignWithCoefficient(CPrivateKey skPtr, void *msg,
    size_t len, size_t player, size_t *players, size_t T);

CInsecureSignature CThresholdAggregateUnitSigs(void **sigs, size_t numSigs,
    void *msg, size_t len, size_t *players, size_t T);


// C helper funcs
size_t* AllocIntPtr(size_t size);
void SetIntPtrVal(size_t *ptr, size_t value, int index);
size_t GetIntPtrVal(size_t *ptr, int index);
void FreeIntPtr(size_t *ptr);

#ifdef __cplusplus
}
#endif
#endif  // GO_BINDINGS_THRESHOLD_H_
