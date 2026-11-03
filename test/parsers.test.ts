import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePackageLock, parsePnpmLock, parseYarnLock } from "../src/parsers/js.ts";
import { parseCargoLock, parseGoMod, parseGradle, parseRequirements, parseVersionCatalog } from "../src/parsers/other.ts";
import { cleanDomain, parseDockerfile, parseWorkflow } from "../src/parsers/infra.ts";
import { compareVersions, cvss3, fixedVersion, severityOf } from "../src/osv.ts";

test("package-lock v3: nested resolution, direct + dev flags, edges", () => {
  const r = parsePackageLock(JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { a: "^1" }, devDependencies: { t: "^1" } },
      "node_modules/a": { version: "1.0.0", dependencies: { b: "^2" } },
      "node_modules/a/node_modules/b": { version: "2.0.0" },
      "node_modules/b": { version: "1.0.0" },
      "node_modules/t": { version: "1.0.0", dev: true, dependencies: { b: "^1" } },
    },
  }));
  const get = (k: string) => r.packages.find((p) => `${p.name}@${p.version}` === k)!;
  assert.equal(get("a@1.0.0").direct, true);
  assert.equal(get("b@2.0.0").direct, false);
  assert.equal(get("t@1.0.0").scope, "dev");
  assert.deepEqual(r.edges, [
    { parent: "a@1.0.0", child: "b@2.0.0" }, // nested copy wins
    { parent: "t@1.0.0", child: "b@1.0.0" }, // hoisted copy
  ]);
});

test("pnpm v9 snapshots + importers", () => {
  const r = parsePnpmLock(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      next:
        specifier: ^16
        version: 16.1.1(react@19.0.0)
packages:
  next@16.1.1:
    resolution: {integrity: x}
snapshots:
  next@16.1.1(react@19.0.0):
    dependencies:
      postcss: 8.4.31
  postcss@8.4.31: {}
`);
  assert.ok(r.packages.find((p) => p.name === "next" && p.version === "16.1.1" && p.direct));
  assert.deepEqual(r.edges, [{ parent: "next@16.1.1", child: "postcss@8.4.31" }]);
});

test("yarn classic", () => {
  const r = parseYarnLock(`# yarn lockfile v1

"@scope/a@^1.0.0":
  version "1.2.0"
  dependencies:
    b "^2.0.0"

b@^2.0.0, b@^2.1.0:
  version "2.1.3"
`, { dependencies: { "@scope/a": "^1.0.0" } });
  assert.ok(r.packages.find((p) => p.name === "@scope/a" && p.direct));
  assert.deepEqual(r.edges, [{ parent: "@scope/a@1.2.0", child: "b@2.1.3" }]);
});

test("Cargo.lock: registry crates only, direct from workspace", () => {
  const r = parseCargoLock(`
[[package]]
name = "myapp"
version = "0.1.0"
dependencies = [
 "serde",
 "rustls 0.23.35",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rustls"
version = "0.23.35"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde"]
`);
  assert.deepEqual(r.packages.map((p) => [p.name, p.direct]), [["serde", true], ["rustls", true]]);
  assert.deepEqual(r.edges, [{ parent: "rustls@0.23.35", child: "serde@1.0.200" }]);
});

test("go.mod, requirements, gradle + catalog", () => {
  const go = parseGoMod("module x\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/net v0.1.0 // indirect\n)\n");
  assert.deepEqual(go.packages.map((p) => [p.name, p.version, p.direct]), [["github.com/a/b", "1.2.3", true], ["golang.org/x/net", "0.1.0", false]]);

  const py = parseRequirements("Django==4.2.1\nrequests>=2\nflask_cors==4.0.0 # pinned\n");
  assert.deepEqual(py.packages.map((p) => `${p.name}@${p.version}`), ["django@4.2.1", "flask-cors@4.0.0"]);

  const cat = parseVersionCatalog('[versions]\ncore = "1.13.0"\n[libraries]\nandroidx-core-ktx = { module = "androidx.core:core-ktx", version.ref = "core" }\n');
  const g = parseGradle('implementation(libs.androidx.core.ktx)\ntestImplementation("junit:junit:4.13.2")\n', cat);
  assert.deepEqual(g.packages.map((p) => [p.name, p.version, p.scope]), [["androidx.core:core-ktx", "1.13.0", "prod"], ["junit:junit", "4.13.2", "dev"]]);
});

test("infra: docker stages, action pinning, domains", () => {
  const d = parseDockerfile("FROM node:20 AS build\nFROM build\nFROM nginx\n", "Dockerfile");
  assert.deepEqual(d.map((i) => [i.value, i.warning]), [["node:20", undefined], ["nginx", "no tag (implicit :latest)"]]);

  const w = parseWorkflow("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local\n      - uses: x/y@" + "a".repeat(40) + "\n", "ci.yml");
  assert.equal(w.length, 2);
  assert.match(w[0].warning!, /mutable/);
  assert.equal(w[1].warning, undefined);

  assert.equal(cleanDomain("https://tvs.vote/"), "tvs.vote");
  assert.equal(cleanDomain("connect.example.com"), null);
  assert.equal(cleanDomain("localhost:3000"), null);
});

test("severity: CVSS 3.1 math + labels", () => {
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(severityOf({ database_specific: { severity: "MEDIUM" } }), "MODERATE");
  assert.equal(severityOf({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }), "CRITICAL");
});

test("fixed version: smallest fix above installed", () => {
  const v = { affected: [{ package: { ecosystem: "npm", name: "next" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "15.5.9" }, { introduced: "16.0.0" }, { fixed: "16.4.1" }] }] }] };
  assert.equal(fixedVersion(v, { ecosystem: "npm", name: "next", version: "16.1.1" }), "16.4.1");
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
});
