const assert = require('assert');
const blsjs = require('../../js_build/js-bindings/blsjs.js');

blsjs().then((blsjs) => {
    const modules = [
        'AugSchemeMPL',
        'BasicSchemeMPL',
        'G1Element',
        'G2Element',
        'PopSchemeMPL',
        'PrivateKey',
        'Util'
    ];

    // ensure all present
    for (var i = 0; i < modules.length; i++) {
        const m = modules[i];
        if (blsjs[m] === undefined) {
            console.log(`undefined required module ${m}`);
            process.exit(1);
        }
    }

    const {
        AugSchemeMPL,
        BasicSchemeMPL,
        G1Element,
        G2Element,
        PopSchemeMPL,
        PrivateKey,
        Util
    } = blsjs;

    function test_schemes() {
        var seedArray = [
            0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6,
            220, 18, 102, 58, 209, 82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22
        ];
        var seed = Buffer.from(seedArray);

        const msg = Buffer.from([100, 2, 254, 88, 90, 45, 23]);
        const msg2 = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        const sk = BasicSchemeMPL.key_gen(seed);
        const pk = sk.get_g1();

        //assert(sk == PrivateKey.fromBytes(sk.serialize(), false));
        //assert(pk == G1Element.fromBytes(pk.serialize()));

        [BasicSchemeMPL, AugSchemeMPL, PopSchemeMPL].map((Scheme) => {
            const sig = Scheme.sign(sk, msg);
            //assert(sig == G2Element.fromBytes(Buffer.from(sig)));
            assert(Scheme.verify(pk, msg, sig));
        });

        var seed = Buffer.concat([Buffer.from([1]), seed.slice(1)]);
        const sk1 = BasicSchemeMPL.key_gen(seed);
        const pk1 = sk1.get_g1();
        var seed = Buffer.concat([Buffer.from([2]), seed.slice(1)]);
        const sk2 = BasicSchemeMPL.key_gen(seed);
        const pk2 = sk2.get_g1();

        [BasicSchemeMPL, AugSchemeMPL, PopSchemeMPL].map((Scheme) => {
            // Aggregate same message
            const agg_pk = pk1.add(pk2);
            var sig1, sig2;
            if (Scheme === AugSchemeMPL) {
                sig1 = Scheme.sign_prepend(sk1, msg, agg_pk);
                sig2 = Scheme.sign_prepend(sk2, msg, agg_pk);
            } else {
                sig1 = Scheme.sign(sk1, msg);
                sig2 = Scheme.sign(sk2, msg);
            }

            var agg_sig = Scheme.aggregate([sig1, sig2]);
            assert(Scheme.verify(agg_pk, msg, agg_sig));

            // Aggregate different message
            sig1 = Scheme.sign(sk1, msg)
            sig2 = Scheme.sign(sk2, msg2)
            agg_sig = Scheme.aggregate([sig1, sig2])
            assert(Scheme.aggregate_verify([pk1, pk2], [msg, msg2], agg_sig));

            // HD keys
            const child = Scheme.derive_child_sk(sk1, 123);
            const childU = Scheme.derive_child_sk_unhardened(sk1, 123);
            const childUPk = Scheme.derive_child_pk_unhardened(pk1, 123);

            const sig_child = Scheme.sign(child, msg);
            assert(Scheme.verify(child.get_g1(), msg, sig_child));

            const sigU_child = Scheme.sign(childU, msg);
            assert(Scheme.verify(childUPk, msg, sigU_child));
        });
    }

    test_schemes();
}).then(function() {
    console.log("\nAll tests passed.");
});

const copyright = [
    'Copyright 2020 Chia Network Inc',
    'Licensed under the Apache License, Version 2.0 (the "License");',
    'you may not use this file except in compliance with the License.',
    'You may obtain a copy of the License at',
    'http://www.apache.org/licenses/LICENSE-2.0',
    'Unless required by applicable law or agreed to in writing, software',
    'distributed under the License is distributed on an "AS IS" BASIS,',
    'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.',
    'See the License for the specific language governing permissions and',
    'limitations under the License.'
];
