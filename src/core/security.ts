import fs from "node:fs";
import path from "node:path";
import type { Finding, SecuritySummary } from "./types.js";

interface SecurityRule {
	pattern: RegExp;
	title: string;
	severity: "critical" | "high" | "medium" | "low";
	description: string;
	why: string;
	remediation: string;
	confidence: number;
}

const CREDENTIAL_RULES: SecurityRule[] = [
	{
		pattern: /\bAKIA[0-9A-Z]{16}\b/,
		title: "AWS Access Key Exposed",
		severity: "critical",
		description: "AWS access key ID found in source code",
		why: "AWS credentials grant access to cloud infrastructure. Exposed keys can be used to launch attacks, steal data, or incur massive costs.",
		remediation: "1. Revoke the key immediately in AWS IAM console\n2. Remove from source code\n3. Commit removal to git history\n4. Use AWS IAM roles or temporary credentials instead",
		confidence: 0.99
	},
	{
		pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
		title: "GitHub Token Exposed",
		severity: "critical",
		description: "GitHub personal access token or OAuth token detected",
		why: "GitHub tokens provide full repository access. Exposed tokens can be used to modify code, delete repositories, or access private data.",
		remediation: "1. Revoke immediately at github.com/settings/tokens\n2. Remove from code and history\n3. Use GitHub Actions secrets for CI/CD\n4. Never hardcode tokens in source",
		confidence: 0.95
	},
	{
		pattern: /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/,
		title: "Stripe API Key Exposed",
		severity: "critical",
		description: "Stripe API key (publishable or secret) found in repository",
		why: "Stripe keys can be used to process fraudulent transactions, steal payment data, or create unauthorized charges.",
		remediation: "1. Rotate keys in Stripe dashboard\n2. Remove from code\n3. Load from environment variables (process.env.STRIPE_KEY)\n4. Use restricted API keys with minimal permissions",
		confidence: 0.92
	},
	{
		pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
		title: "Private Key Material Exposed",
		severity: "critical",
		description: "Private key found directly in repository",
		why: "Private keys compromise all encryption and authentication. They can be used to impersonate your application or decrypt all communications.",
		remediation: "1. Assume the key is compromised and rotate it\n2. Remove from git history using BFG or git-filter-branch\n3. Store keys in secure vaults (HashiCorp Vault, AWS Secrets Manager)\n4. Use key management services in production",
		confidence: 0.99
	},
	{
		pattern: /(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*["'][^"'$\n]{8,}["']/i,
		title: "Hardcoded Secret/Password",
		severity: "critical",
		description: "Hardcoded credential found in source code",
		why: "Hardcoded secrets are visible to anyone with repository access and can be extracted by automated tools scanning repositories.",
		remediation: "1. Remove the hardcoded value\n2. Add to .env file (not tracked in git)\n3. Load from environment variables at runtime\n4. Use process.env.SECRET_NAME in your code",
		confidence: 0.8
	},
	{
		pattern: /(?:postgres|mysql|mongodb(?:\+srv)?|redis)\:\/\/(?:[^:]+):(?:[^@]+)@[^\s"']+/i,
		title: "Database Connection String with Credentials",
		severity: "critical",
		description: "Database URL with embedded credentials found",
		why: "Database connection strings with passwords grant direct access to databases. Compromised credentials allow data theft, modification, or deletion.",
		remediation: "1. Reset database passwords immediately\n2. Remove connection string from code\n3. Load DATABASE_URL from environment variables\n4. Use IAM database authentication where possible",
		confidence: 0.96
	},
	{
		pattern: /(?:api|auth|secret|key)[\s]*=[\s]*['\"]\S{20,}['\"]|\bBEARER\s+[A-Za-z0-9._\-]+/i,
		title: "API Token/Bearer Token Exposed",
		severity: "high",
		description: "API token or Bearer token found in code",
		why: "API tokens authenticate requests to external services. Exposed tokens allow unauthorized access to those services.",
		remediation: "1. Revoke the token in the service's dashboard\n2. Move to environment variables\n3. Use token rotation strategies\n4. Implement token scoping with minimal permissions",
		confidence: 0.75
	}
];

const CODE_PATTERN_RULES: SecurityRule[] = [
	{
		pattern: /\beval\s*\(/,
		title: "Use of eval() Detected",
		severity: "high",
		description: "The eval() function is used to execute arbitrary code",
		why: "eval() can execute untrusted code, leading to code injection attacks. It also makes code harder to analyze and slower to execute.",
		remediation: "1. Replace with safer alternatives (JSON.parse, Function constructor with limited scope)\n2. Use code generators at build time instead of runtime\n3. If dynamic code is needed, use Web Workers with strict policies",
		confidence: 0.85
	},
	{
		pattern: /\bexec\s*\(|child_process\.(exec|execSync)\s*\(/,
		title: "Use of exec() for Shell Commands",
		severity: "critical",
		description: "Shell command execution detected without proper escaping",
		why: "exec() is vulnerable to command injection. User input passed to shell commands can execute arbitrary code with process privileges.",
		remediation: "1. Use execFile() or spawn() with array-based arguments instead\n2. Never pass user input directly to shell commands\n3. Use parameterized/escaped commands\n4. Validate and sanitize all inputs\nExample: execFile('ls', ['-l', userInput]) instead of exec(`ls -l ${userInput}`)",
		confidence: 0.9
	},
	{
		pattern: /\bSQL\s*\.\s*raw|\.query\s*\(\s*['\"].*\$|\.execute\s*\(\s*['\"].*\$/,
		title: "Potential SQL Injection",
		severity: "critical",
		description: "Raw SQL query with potential variable interpolation detected",
		why: "SQL injection allows attackers to modify queries, bypass authentication, read/write unauthorized data, or drop databases.",
		remediation: "1. Always use parameterized queries/prepared statements\n2. Use ORM libraries (Sequelize, TypeORM, Prisma)\n3. Never concatenate user input into SQL strings\nExample: db.query('SELECT * FROM users WHERE id = ?', [userId]) instead of `...WHERE id = ${userId}`",
		confidence: 0.75
	},
	{
		pattern: /innerHTML\s*=|\.html\s*\(/,
		title: "XSS Vulnerability: Unsafe HTML Injection",
		severity: "high",
		description: "Direct DOM manipulation using innerHTML detected",
		why: "Setting innerHTML with user-controlled data can execute injected JavaScript. Attackers can steal cookies, sessions, or perform actions as the user.",
		remediation: "1. Use textContent instead of innerHTML when possible\n2. Use framework templating (React, Vue) which auto-escapes\n3. Use DOMPurify to sanitize HTML before setting\n4. Use innerText for plain text content",
		confidence: 0.8
	},
	{
		pattern: /dangerouslySetInnerHTML|v-html|{{{|\[\[\s*[^}]*\]\]/,
		title: "Dangerous HTML Binding Detected",
		severity: "high",
		description: "Unsafe HTML binding in React/Vue template detected",
		why: "Frameworks flag HTML binding as dangerous because it bypasses built-in XSS protection. User data passed this way can execute scripts.",
		remediation: "1. Avoid dangerouslySetInnerHTML - use regular JSX instead\n2. If HTML content is necessary, sanitize it with DOMPurify\n3. Use framework-safe alternatives for dynamic content\n4. Validate and sanitize all external HTML before rendering",
		confidence: 0.85
	},
	{
		pattern: /\bfs\.readFile|readFileSync|fs\.access|fs\.chmod\s*\(\s*userInput|path\.resolve|path\.join.*userInput/,
		title: "Potential Path Traversal Vulnerability",
		severity: "high",
		description: "File system operation with unsanitized user input detected",
		why: "Path traversal allows attackers to access files outside intended directories (e.g., ../../etc/passwd), potentially exposing sensitive data.",
		remediation: "1. Validate file paths against a whitelist\n2. Use path.relative() to detect traversal attempts\n3. Ensure paths stay within allowed directory\n4. Use fs.realpath() to resolve to canonical path and verify it's in allowed directory",
		confidence: 0.7
	},
	{
		pattern: /\bsetTimeout|setInterval\s*\(\s*userInput|Function\s*\(\s*userInput/,
		title: "Dynamic Code Execution from User Input",
		severity: "critical",
		description: "User-controlled code execution detected",
		why: "Executing user-supplied strings as code allows complete system compromise. Attackers can read files, modify data, or escalate privileges.",
		remediation: "1. Never execute user input as code\n2. Use strict input validation\n3. Use alternative approaches (configuration objects, templates)\n4. Use code sandboxing if dynamic code is necessary",
		confidence: 0.8
	},
	{
		pattern: /\.disabled\s*=\s*false|disabled\s*=\s*['\"]false['\"]|\.removeAttribute\s*\(\s*['\"]disabled/,
		title: "Security Control Disabled",
		severity: "high",
		description: "Disabled HTML/CSS security controls detected",
		why: "Disabling disabled attributes or security-related controls can allow unintended user interactions or bypass validation.",
		remediation: "1. Use proper input validation and authorization\n2. Keep security controls enabled\n3. Validate on both client and server side\n4. Use hidden form fields instead of manipulating disabled state",
		confidence: 0.65
	}
];

const INSECURE_PRACTICE_RULES: SecurityRule[] = [
	{
		pattern: /\/\/ TODO.*(?:fix|hack|insecure|vulnerability|bypass|skip validation)/i,
		title: "Security TODO Comment Found",
		severity: "medium",
		description: "TODO comment indicating potential security issue",
		why: "Unfixed security-related TODOs can remain in production indefinitely, leaving known vulnerabilities unaddressed.",
		remediation: "1. Complete the TODO before merging\n2. Create a ticket if it needs to wait\n3. Remove the comment if already addressed\n4. Use a linter to enforce TODO completion",
		confidence: 0.6
	},
	{
		pattern: /crypto\.randomBytes|Math\.random\s*\(\)\s*\./,
		title: "Weak Randomness for Security",
		severity: "high",
		description: "Math.random() used for security-sensitive operations",
		why: "Math.random() is not cryptographically secure. It's predictable and unsuitable for generating tokens, keys, or security-related random values.",
		remediation: "1. Use crypto.randomBytes() for Node.js\n2. Use crypto.getRandomValues() for browsers\n3. Use secure random libraries (uuid v4 for IDs)\n4. Never use Math.random() for tokens or keys",
		confidence: 0.85
	},
	{
		pattern: /\b(?:http|telnet|ftp|ws):\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
		title: "Insecure Protocol Used",
		severity: "high",
		description: "Unencrypted protocol (HTTP, FTP, etc.) used for remote communication",
		why: "Unencrypted protocols transmit data in plaintext. Attackers on the network can read all traffic including authentication credentials.",
		remediation: "1. Use HTTPS instead of HTTP\n2. Use SFTP instead of FTP\n3. Use WSS (WebSocket Secure) instead of WS\n4. Enforce TLS 1.2 or higher",
		confidence: 0.8
	},
	{
		pattern: /verify\s*[:=]\s*false|ssl.*verify\s*[:=]\s*false|insecure\s*[:=]\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]/,
		title: "Certificate Verification Disabled",
		severity: "critical",
		description: "SSL/TLS certificate verification disabled",
		why: "Disabling certificate verification allows man-in-the-middle attacks. Without verification, you can't ensure you're connecting to the intended server.",
		remediation: "1. Enable certificate verification by default\n2. Only disable for development with local self-signed certs\n3. Use proper certificate pinning for high-security applications\n4. Never disable verification in production",
		confidence: 0.9
	},
	{
		pattern: /process\.exit|process\.abort|exit\s*\(\s*[^0]\)/,
		title: "Unexpected Process Termination",
		severity: "low",
		description: "Process exit or abort called without proper cleanup",
		why: "Calling process.exit() directly may skip cleanup (file handles, database connections), corrupting data or leaving resources hanging.",
		remediation: "1. Use graceful shutdown handlers\n2. Close connections before exiting\n3. Use error handling instead of exit\n4. Set exit code appropriately",
		confidence: 0.6
	},
	{
		pattern: /console\.log.*(?:password|secret|token|key|auth|credential)/i,
		title: "Sensitive Data Logged",
		severity: "high",
		description: "Sensitive information logged to console",
		why: "Logs are often stored and accessible to multiple people. Sensitive data in logs can leak credentials, keys, or personal information.",
		remediation: "1. Never log passwords, tokens, or keys\n2. Redact sensitive fields before logging\n3. Use logging libraries that support field masking\n4. Review logs for sensitive data regularly",
		confidence: 0.75
	},
	{
		pattern: /\.split\s*\(\s*['\"][^'\"]*['\"]\s*\)\.join\s*\(\s*['\"][^'\"]*['\"]\s*\)|replace\s*\(\s*\/.*\/g/,
		title: "Potential Regexp DoS Vulnerability",
		severity: "medium",
		description: "Complex string manipulation that could be vulnerable to ReDoS",
		why: "Regular expressions with poor design can cause catastrophic backtracking, leading to CPU exhaustion (Denial of Service).",
		remediation: "1. Use simple string operations instead of regex when possible\n2. Test regex performance with large inputs\n3. Use regex libraries designed to prevent ReDoS\n4. Set regex execution timeouts",
		confidence: 0.5
	}
];

const MISSING_SECURITY_HEADERS: SecurityRule[] = [
	{
		pattern: /(?:app|server|router)\.get|\.post|\.use.*(?:express|fastify|koa)/,
		title: "Missing Security Headers Implementation",
		severity: "medium",
		description: "No security headers middleware detected",
		why: "Missing HTTP security headers leave applications vulnerable to common attacks like XSS, clickjacking, and MIME-sniffing.",
		remediation: "1. Install helmet.js for Express or equivalent\n2. Add these headers:\n   - Content-Security-Policy\n   - X-Frame-Options: DENY\n   - X-Content-Type-Options: nosniff\n   - Strict-Transport-Security\n3. Use helmet() middleware in Express",
		confidence: 0.4
	},
	{
		pattern: /(?:cors|CORS)\s*[:=]|app\.use.*cors/,
		title: "CORS Configured - Verify Origin Whitelist",
		severity: "medium",
		description: "CORS is enabled - ensure origins are properly restricted",
		why: "Misconfigured CORS (e.g., allowing *) allows any website to make requests to your API, potentially exposing user data.",
		remediation: "1. Never use origin: '*' in production\n2. Explicitly whitelist trusted origins\n3. Use credentials: 'include' only with specific origins\n4. Example: cors({ origin: ['https://trusted.com'] })",
		confidence: 0.6
	}
];

function createFinding(rule: SecurityRule, file: string, line: number, confidence: number): Finding {
	return {
		id: `security.${rule.title.toLowerCase().replace(/\s+/g, "-")}:${file}:${line}`,
		category: "security",
		severity: rule.severity,
		title: rule.title,
		description: rule.description,
		file,
		line,
		remediation: `${rule.why}\n\n🔧 Fix:\n${rule.remediation}`,
		confidence
	};
}

function isIgnoredSecretFile(relative: string): boolean {
	const normalized = relative.replace(/\\/g, "/");
	const baseName = normalized.split("/").pop() ?? normalized;
	return /(^|\/)debug\.keystore$/i.test(normalized) || /^debug\.keystore$/i.test(baseName);
}

export function scanSecurity(root: string, files: string[]): SecuritySummary {
	const findings: Finding[] = [];
	let scannedFiles = 0;
	const alreadyReported = new Set<string>();

	for (const relative of files) {
		// Check for environment files
		if (relative === ".env" || /^\.env\./.test(relative)) {
			findings.push({
				id: `security.env:${relative}`,
				category: "security",
				severity: "high",
				title: "Environment file may be committed",
				description: "An environment file is tracked in git, which can contain credentials.",
				file: relative,
				remediation: "❌ Risk:\nEnvironment files often contain database passwords, API keys, and other secrets.\n\n🔧 Fix:\n1. Remove from git history: git rm --cached .env\n2. Add to .gitignore: echo '.env' >> .gitignore\n3. Rotate any secrets that were exposed\n4. Store secrets in CI/CD environment variables or secret managers",
				confidence: 1
			});
			continue;
		}

		if (isIgnoredSecretFile(relative)) {
			continue;
		}

		// Check for common secret file patterns
		if (/\.pem|\.cert|secrets?\.(?:json|yaml|yml|txt)|keystore\.jks|\.pgp|\.gpg/i.test(relative) || /(^|\/)[^\/]+\.key$/i.test(relative)) {
			findings.push({
				id: `security.secret-file:${relative}`,
				category: "security",
				severity: "critical",
				title: "Secret/Key file in repository",
				description: "A file containing cryptographic material or secrets was found.",
				file: relative,
				remediation: "❌ Risk:\nSecret files grant access to encrypted data and authentication systems.\n\n🔧 Fix:\n1. Remove immediately: git rm --cached <file>\n2. Rotate all keys/certificates\n3. Add pattern to .gitignore\n4. Store in secure key management system (AWS KMS, HashiCorp Vault)",
				confidence: 0.95
			});
			continue;
		}

		const full = path.join(root, relative);
		let content: string;
		try {
			content = fs.readFileSync(full, "utf8");
			scannedFiles++;
		} catch {
			continue;
		}

		// Skip large files
		if (content.length > 2_000_000) continue;

		const lines = content.split("\n");
		const reportedLines = new Set<number>();

		// Apply all security rules
		const allRules = [...CREDENTIAL_RULES, ...CODE_PATTERN_RULES, ...INSECURE_PRACTICE_RULES, ...MISSING_SECURITY_HEADERS];

		for (const rule of allRules) {
			let searchContent = content;
			let match: RegExpExecArray | null;
			const ruleKey = `${rule.title}:${relative}`;

			// Find first match only to avoid duplicates
			match = rule.pattern.exec(searchContent);
			if (!match) continue;

			// Skip if we already reported this issue in this file
			if (alreadyReported.has(ruleKey)) continue;
			alreadyReported.add(ruleKey);

			const lineNumber = searchContent.slice(0, match.index).split("\n").length;
			if (reportedLines.has(lineNumber)) continue;
			reportedLines.add(lineNumber);

			findings.push(createFinding(rule, relative, lineNumber, rule.confidence));
		}
	}

	return { findings, scannedFiles };
}
