const loadBLS = require("../../js_build/js-bindings/blsjs.js");

describe("AugSchemeMPL", () => {
  let BLS;
  
  beforeAll(async () => {
    BLS = await loadBLS();
  });
  
  test("test_aggregate_verify_zero_items", () => {
    expect(BLS.AugSchemeMPL.aggregate_verify([], [], new BLS.G2Element())).toBeTruthy();
  });
});
