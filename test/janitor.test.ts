import { test } from "node:test";
import assert from "node:assert/strict";
import { scanDeprecations, expiredDeprecations } from "../src/janitor.ts";

const NOW = new Date(2026, 5, 1); // 2026-06-01

test("flags a dated marker only once its date has passed", () => {
  assert.equal(expiredDeprecations("// @deprecate 01-15-2026\nconst a = 1;", NOW).length, 1, "past date is expired");
  assert.equal(expiredDeprecations("// @deprecate 12-31-2026\nconst a = 1;", NOW).length, 0, "future date is not");
  const d = scanDeprecations("// @deprecate 01-15-2026 reason: unused helper", NOW)[0];
  assert.equal(d.date, "01-15-2026");
  assert.equal(d.reason, "unused helper");
  assert.equal(d.expired, true);
});

test("an undated marker is treated as expired (removed next run)", () => {
  const d = scanDeprecations("// @deprecate\n// const old = 1;", NOW);
  assert.equal(d.length, 1);
  assert.equal(d[0].date, null);
  assert.equal(d[0].expired, true);
  assert.equal(scanDeprecations("// @deprecate reason: dead flag", NOW)[0].reason, "dead flag");
});

test("same-day is not yet expired, and plain code is ignored", () => {
  assert.equal(expiredDeprecations("// @deprecate 06-01-2026\nx();", NOW).length, 0, "expires the day after");
  assert.deepEqual(scanDeprecations("const deprecatedThing = 1; // not a marker", NOW), []);
  assert.deepEqual(scanDeprecations("// @deprecated (JSDoc, different tag)", NOW), [], "JSDoc @deprecated isn't @deprecate");
});
