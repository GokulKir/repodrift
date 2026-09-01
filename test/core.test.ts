import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { analyzeDependencies } from "../src/core/dependencies.js";
import { calculateHealthScore } from "../src/core/engine.js";
import { scanRepository } from "../src/core/scanner.js";
import { scanSecurity } from "../src/core/security.js";
import type { Finding } from "../src/core/types.js";

const temporaryRoots: string[] = [];

afterEach(() => { for (const root of temporaryRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

function fixture(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "repodrift-"));
  temporaryRoots.push(root);
  return root;
}

describe("repository analyzers", () => {
  it("scans files, classifications, and ignore patterns", () => {
    const root = fixture();
    fs.mkdirSync(path.join(root, "src"));
    fs.mkdirSync(path.join(root, "generated"));
    fs.writeFileSync(path.join(root, "src/app.ts"), "export const app = true;\n");
    fs.writeFileSync(path.join(root, "README.md"), "# Fixture\n");
    fs.writeFileSync(path.join(root, ".repodriftignore"), "generated/\n");
    fs.writeFileSync(path.join(root, "generated/out.js"), "generated\n");
    const result = scanRepository(root);
    assert.equal(result.sourceFiles, 1);
    assert.equal(result.documentationFiles, 1);
    assert.equal(result.files.includes("generated/out.js"), false);
  });

  it("detects credential-like values with locations", () => {
    const root = fixture();
    const credential = ["ghp_", "123456789012345678901234"].join("");
    fs.writeFileSync(path.join(root, "config.ts"), `const token = '${credential}';\n`);
    const result = scanSecurity(root, ["config.ts"]);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.line, 1);
    assert.equal(result.findings[0]?.category, "security");
  });

  it("reports a missing lockfile without inventing package issues", () => {
    const root = fixture();
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ dependencies: { commander: "^1.0.0" } }));
    const result = analyzeDependencies(root);
    assert.equal(result.total, 1);
    assert.equal(result.findings[0]?.id, "dependencies.no-lockfile");
  });

  it("reports deprecated packages recorded in an npm lockfile", () => {
    const root = fixture();
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ dependencies: { legacy: "1.0.0" } }));
    fs.writeFileSync(path.join(root, "package-lock.json"), JSON.stringify({ packages: { "": {}, "node_modules/legacy": { deprecated: "Use a maintained alternative." } } }));
    const result = analyzeDependencies(root);
    assert.equal(result.findings[0]?.id, "dependencies.deprecated:legacy");
  });

  it("calculates deterministic weighted health scores", () => {
    const finding: Finding = { id: "x", category: "security", severity: "high", title: "x", description: "x", remediation: "x", confidence: 1 };
    const first = calculateHealthScore([finding], true);
    const second = calculateHealthScore([finding], true);
    assert.deepEqual(first, second);
    assert.equal(first.score, 90);
    assert.equal(first.grade, "A");
  });
});