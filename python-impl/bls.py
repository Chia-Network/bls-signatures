from ec import JacobianPoint, default_ec
from util import hash256


class BLS:
    def hash_pks(num_outputs, public_keys):
        """
        Construction from https://eprint.iacr.org/2018/483.pdf
        Two hashes are performed for speed.
        """
        input_bytes = b''.join([pk.serialize() for pk in public_keys])
        pk_hash = hash256(input_bytes)
        order = public_keys[0].value.ec.n

        computed_Ts = []
        for i in range(num_outputs):
            t = int.from_bytes(hash256(i.to_bytes(4, "big") + pk_hash), "big")
            computed_Ts.append(t % order)

        return computed_Ts


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
