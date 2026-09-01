import fs from "node:fs";
import path from "node:path";
import type { Finding, SecuritySummary } from "./types.js";

const SECRET_RULES: Array<[RegExp, string, string]> = [
	[/\bAKIA[0-9A-Z]{16}\b/, "AWS access key", "Rotate the key and move credentials to a secret manager."],
	[/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/, "GitHub token", "Revoke the token and use environment-based credentials."],
	[/\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/, "API credential", "Rotate the credential and load it from the environment."],
	[/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, "Private key", "Remove the key from source control and rotate it."],
	[/(?:password|passwd|secret|token)\s*[:=]\s*["'][^"'$]{8,}["']/i, "Hardcoded credential", "Move the credential to an environment variable."],
	[/(?:postgres|mysql|mongodb(?:\+srv)?)\:\/\/[^\s"']+/i, "Database URL", "Remove the URL and use a secret-managed environment variable."]
];

export function scanSecurity(root: string, files: string[]): SecuritySummary {
	const findings: Finding[] = [];
	let scannedFiles = 0;
	for (const relative of files) {
		if (relative === ".env" || /^\.env\./.test(relative)) {
			findings.push({ id: `security.env:${relative}`, category: "security", severity: "high", title: "Environment file may be committed", description: "An environment file can contain credentials and should not be tracked.", file: relative, remediation: "Remove it from Git, rotate its secrets, and add it to .gitignore.", confidence: 1 });
			continue;
		}
		const full = path.join(root, relative);
		let content: string;
		try { content = fs.readFileSync(full, "utf8"); scannedFiles++; } catch { continue; }
		if (content.length > 2_000_000) continue;
		for (const [pattern, title, remediation] of SECRET_RULES) {
			const match = pattern.exec(content);
			if (!match) continue;
			const line = content.slice(0, match.index).split("\n").length;
			findings.push({ id: `security.${title.toLowerCase().replaceAll(" ", "-")}:${relative}:${line}`, category: "security", severity: title === "Private key" ? "critical" : "high", title: `Potential ${title}`, description: "A credential-like value was detected in repository content.", file: relative, line, remediation, confidence: 0.85 });
			break;
		}
	}
	return { findings, scannedFiles };
}
