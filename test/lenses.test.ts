import { test } from "node:test";
import assert from "node:assert/strict";
import { AI_LENSES, aiLens } from "../src/lenses.ts";
import { lensComment } from "../src/agents.ts";
import type { ReviewFinding } from "../src/review.ts";

const finding = (over: Partial<ReviewFinding> = {}): ReviewFinding => ({
  severity: "high", category: "security", file: "src/x.ts", line: 3, title: "t", detail: "d", suggestion: "s", ...over,
});

test("the two AI lenses exist with their own GitHub contexts", () => {
  assert.deepEqual(AI_LENSES.map((l) => l.id).sort(), ["a11y", "crimson"]);
  assert.equal(aiLens("crimson")!.context, "Mycelium crimson");
  assert.equal(aiLens("a11y")!.context, "Mycelium a11y");
  assert.equal(aiLens("nope"), undefined);
});

test("Crimson blocks on high and critical only; a11y never blocks", () => {
  const crimson = aiLens("crimson")!;
  assert.equal(crimson.advisory, false);
  assert.equal(crimson.blocks(finding({ severity: "critical" })), true);
  assert.equal(crimson.blocks(finding({ severity: "high" })), true);
  assert.equal(crimson.blocks(finding({ severity: "medium" })), false);
  assert.equal(crimson.blocks(finding({ severity: "low" })), false);

  const a11y = aiLens("a11y")!;
  assert.equal(a11y.advisory, true);
  assert.equal(a11y.blocks(finding({ severity: "critical" })), false, "advisory lens blocks nothing");
});

test("lensComment neutralises model output and can't ping people or post live links", () => {
  const body = lensComment(aiLens("crimson")!, "o/r", "abcdef1234", {
    summary: "ping @octocat and see https://evil.test",
    findings: [finding({ title: "calls @someone", detail: "posts to https://evil.test/x and refs #123" })],
  });
  assert.ok(!body.includes("@octocat"), "no bare mention survives");
  assert.ok(!/https:\/\/evil\.test(?!​)/.test(body) || body.includes(":​//"), "scheme is defanged");
  assert.ok(body.includes("Mycelium crimson") && body.includes("sent back"));
  assert.ok(body.includes("calls") && body.includes("**Fix:**"));
});

test("an advisory lens comment says so and never says sent back", () => {
  const body = lensComment(aiLens("a11y")!, "o/r", "abcdef1234", { summary: "s", findings: [finding({ category: "a11y" })] });
  assert.ok(body.includes("advisory"));
  assert.ok(!body.includes("sent back"));
});
