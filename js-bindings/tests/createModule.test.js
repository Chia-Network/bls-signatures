const loadBLS = require("../../js_build/js-bindings/blsjs.js");
let BLS;

beforeAll(async () => {
  BLS = await loadBLS();
});

test("Ensure all modules are present", () => {
  const modules = [
    "AugSchemeMPL",
    "BasicSchemeMPL",
    "Bignum",
    "G1Element",
    "G2Element",
    "PopSchemeMPL",
    "PrivateKey",
    "Util"
  ];
  
  for (let i = 0; i < modules.length; i++) {
    const m = modules[i];
    expect(BLS[m]).toBeDefined();
  }
});
