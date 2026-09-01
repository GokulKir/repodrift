import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import type { DependencySummary, Finding } from "./types.js";

export function analyzeDependencies(root: string, options: { audit?: boolean } = {}): DependencySummary {
	const lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"].filter((file) => fs.existsSync(path.join(root, file)));
	const manifestPath = path.join(root, "package.json");
	if (!fs.existsSync(manifestPath)) return { manifest: null, total: 0, production: 0, development: 0, lockfiles, findings: [] };
	try {
		const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
		const production = Object.keys(manifest.dependencies ?? {}).length;
		const development = Object.keys(manifest.devDependencies ?? {}).length;
		const findings: Finding[] = [];
		if (lockfiles.length === 0 && production + development > 0) findings.push({
			id: "dependencies.no-lockfile", category: "dependencies", severity: "medium", title: "Dependency lockfile is missing",
			description: "Dependencies are declared without a lockfile to pin reproducible versions.", file: "package.json",
			remediation: "Generate and commit the lockfile for your package manager.", confidence: 1
		});
		findings.push(...deprecatedPackages(root, lockfiles));
		if (options.audit && lockfiles.includes("package-lock.json")) findings.push(...npmAudit(root));
		return { manifest: "package.json", total: production + development, production, development, lockfiles, findings };
	} catch {
		return {
			manifest: "package.json", total: 0, production: 0, development: 0, lockfiles, findings: [{
				id: "dependencies.invalid-manifest", category: "dependencies", severity: "high", title: "Invalid package manifest",
				description: "package.json could not be parsed as JSON.", file: "package.json", remediation: "Fix the JSON syntax in package.json.", confidence: 1
			}]
		};
	}
}

function deprecatedPackages(root: string, lockfiles: string[]): Finding[] {
	if (!lockfiles.includes("package-lock.json")) return [];
	try {
		const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8")) as { packages?: Record<string, { deprecated?: string }> };
		return Object.entries(lock.packages ?? {}).filter(([key, value]) => key && value.deprecated).map(([key, value]) => {
			const packageName = key.replace(/^node_modules\//, "");
			return { id: `dependencies.deprecated:${packageName}`, category: "dependencies", severity: "medium", title: `Deprecated dependency: ${packageName}`, description: value.deprecated ?? "This package is marked deprecated by its publisher.", file: "package-lock.json", remediation: `Replace ${packageName} with a maintained alternative and update the lockfile.`, confidence: 1 };
		});
	} catch { return []; }
}

function npmAudit(root: string): Finding[] {
	const result = spawnSync("npm", ["audit", "--json", "--package-lock-only", "--ignore-scripts"], { cwd: root, encoding: "utf8", timeout: 30_000 });
	if (result.error || !result.stdout) return [];
	try {
		const report = JSON.parse(result.stdout) as { vulnerabilities?: Record<string, { severity?: string; via?: Array<{ title?: string; url?: string } | string> }> };
		return Object.entries(report.vulnerabilities ?? {}).map(([packageName, vulnerability]) => {
			const via = vulnerability.via?.find((item): item is { title?: string; url?: string } => typeof item !== "string");
			const severity = normalizeSeverity(vulnerability.severity);
			return { id: `dependencies.audit:${packageName}`, category: "dependencies", severity, title: `Known vulnerability in ${packageName}`, description: via?.title ?? "npm audit reported a known vulnerability in this dependency.", file: "package-lock.json", remediation: `Run npm audit fix, review the suggested update for ${packageName}, and test the change.`, confidence: 1 };
		});
	} catch { return []; }
}

function normalizeSeverity(value: string | undefined): Finding["severity"] {
	return value === "critical" || value === "high" || value === "medium" || value === "low" ? value : "info";
}
