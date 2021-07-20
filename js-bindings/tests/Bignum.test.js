const loadBLS = require("../../js_build/js-bindings/blsjs.js");

let BLS;

beforeAll(async () => {
  BLS = await loadBLS();
});

test("test_bignum", () => {
  const mersenne = BLS.Bignum.from_string('162259276829213363391578010288127', 10);
  expect(mersenne.toString(16).toLowerCase()).toBe("7ffffffffffffffffffffffffff");
});
