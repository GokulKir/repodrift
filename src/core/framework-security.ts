import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";

interface FrameworkDetection {
  framework: string;
  confidence: number;
  version?: string;
}

export interface FrameworkSecurityIssue extends Finding {
  framework: string;
}

/**
 * Detect the framework/technology used in the project
 */
export function detectFrameworks(root: string): FrameworkDetection[] {
  const detected: FrameworkDetection[] = [];
  const packageJsonPath = path.join(root, "package.json");
  
  try {
    const content = fs.readFileSync(packageJsonPath, "utf8");
    const pkg = JSON.parse(content);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    // Next.js detection
    if (deps["next"]) {
      detected.push({ framework: "next", confidence: 0.99, version: deps["next"] });
    }

    // React detection
    if (deps["react"]) {
      detected.push({ framework: "react", confidence: 0.99, version: deps["react"] });
    }

    // React Native detection
    if (deps["react-native"]) {
      detected.push({ framework: "react-native", confidence: 0.99, version: deps["react-native"] });
    }

    // Vue detection
    if (deps["vue"]) {
      detected.push({ framework: "vue", confidence: 0.99, version: deps["vue"] });
    }

    // Express detection
    if (deps["express"]) {
      detected.push({ framework: "express", confidence: 0.99, version: deps["express"] });
    }

    // NestJS detection
    if (deps["@nestjs/core"]) {
      detected.push({ framework: "nestjs", confidence: 0.99, version: deps["@nestjs/core"] });
    }
  } catch {
    // Ignore errors reading package.json
  }

  // Check for iOS project files
  if (fs.existsSync(path.join(root, "ios"))) {
    if (fs.existsSync(path.join(root, "ios", "*.xcodeproj")) || fs.existsSync(path.join(root, "ios", "Podfile"))) {
      detected.push({ framework: "ios", confidence: 0.85 });
    }
  }

  // Check for Android project files
  if (fs.existsSync(path.join(root, "android", "build.gradle")) || fs.existsSync(path.join(root, "android", "settings.gradle"))) {
    detected.push({ framework: "android", confidence: 0.95 });
  }

  return detected;
}

/**
 * Scan Next.js specific security issues
 */
export function scanNextJsSecurity(root: string, files: string[]): FrameworkSecurityIssue[] {
  const findings: FrameworkSecurityIssue[] = [];

  for (const file of files) {
    if (!file.includes("pages") && !file.includes("app") && !file.includes("api")) continue;
    
    const filePath = path.join(root, file);
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }

    // Check for API routes without auth
    if ((file.includes("pages/api") || file.includes("app/api")) && /export\s+(default\s+)?async\s+function\s+\w+/.test(content)) {
      if (!content.includes("auth") && !content.includes("verify") && !content.includes("authenticate")) {
        findings.push({
          id: `next.unprotected-api:${file}`,
          category: "security",
          severity: "high",
          title: "Unprotected API Route",
          description: "API route detected without apparent authentication checks",
          file,
          framework: "next",
          remediation: "Add authentication/authorization checks:\n- Use next-auth for authentication\n- Check JWT tokens or session cookies\n- Validate user permissions before processing requests\n- Consider using middleware for route protection",
          confidence: 0.65
        });
      }
    }

    // Check for exposed environment variables
    if (content.includes("process.env.") && /process\.env\.[A-Z_]/.test(content)) {
      if (!file.includes(".env") && !file.includes("config")) {
        const hasPublicPrefix = /process\.env\.NEXT_PUBLIC_/.test(content);
        if (!hasPublicPrefix && /process\.env\.(API_KEY|SECRET|PASSWORD|TOKEN|DATABASE)/.test(content)) {
          findings.push({
            id: `next.exposed-env:${file}`,
            category: "security",
            severity: "high",
            title: "Sensitive Environment Variable in Client Code",
            description: "Sensitive environment variables accessed in client-side code",
            file,
            framework: "next",
            remediation: "Move sensitive env vars to server-side only:\n- Use getServerSideProps() for server-side access\n- Use API routes for sensitive operations\n- Only prefix with NEXT_PUBLIC_ for client-safe vars\n- Never log sensitive values to console",
            confidence: 0.7
          });
        }
      }
    }

    // Check for deprecated Next.js patterns
    if (content.includes("getInitialProps")) {
      findings.push({
        id: `next.deprecated-api:${file}`,
        category: "security",
        severity: "medium",
        title: "Deprecated getInitialProps Used",
        description: "getInitialProps is deprecated in favor of newer data fetching methods",
        file,
        framework: "next",
        remediation: "Migrate to modern Next.js data fetching:\n- Use getServerSideProps() for server-side rendering\n- Use getStaticProps() for static generation\n- Use App Router with async components in Next.js 13+",
        confidence: 0.8
      });
    }

    // Check for missing CSRF protection
    if (file.includes("api") && /method\s*===\s*['"](POST|PUT|DELETE|PATCH)['"]/.test(content)) {
      if (!content.includes("csrf") && !content.includes("nonce")) {
        findings.push({
          id: `next.missing-csrf:${file}`,
          category: "security",
          severity: "high",
          title: "Missing CSRF Protection on Mutating API Route",
          description: "API route that modifies data lacks CSRF token verification",
          file,
          framework: "next",
          remediation: "Add CSRF protection:\n- Use next-csrf package or implement CSRF tokens\n- Validate X-CSRF-Token header on state-changing requests\n- Use SameSite cookie attribute\n- Consider using built-in Next.js mechanisms",
          confidence: 0.6
        });
      }
    }
  }

  return findings;
}

/**
 * Scan React specific security issues
 */
export function scanReactSecurity(root: string, files: string[]): FrameworkSecurityIssue[] {
  const findings: FrameworkSecurityIssue[] = [];

  for (const file of files) {
    if (!file.endsWith(".jsx") && !file.endsWith(".tsx")) continue;
    
    const filePath = path.join(root, file);
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }

    // Check for dangerouslySetInnerHTML
    if (/dangerouslySetInnerHTML\s*=/.test(content)) {
      const line = content.split("\n").findIndex(l => /dangerouslySetInnerHTML/.test(l)) + 1;
      findings.push({
        id: `react.dangerous-html:${file}:${line}`,
        category: "security",
        severity: "high",
        title: "Dangerous HTML Injection with dangerouslySetInnerHTML",
        description: "dangerouslySetInnerHTML bypasses React's built-in XSS protection",
        file,
        line,
        framework: "react",
        remediation: "Sanitize HTML content before rendering:\n- Use DOMPurify to sanitize untrusted HTML\n- Use react-sanitize-html package\n- Consider storing/rendering as JSX instead\n- Never pass user input directly to dangerouslySetInnerHTML",
        confidence: 0.9
      });
    }

    // Check for missing key prop in lists
    if (/\.map\s*\(\s*\(\w+\)\s*=>/.test(content) && /<\w+/.test(content)) {
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (/\.map\s*\(\s*\(\w+\)\s*=>/.test(lines[i]) && !/key\s*=/.test(lines[i])) {
          const nextLines = lines.slice(i, i + 5).join("\n");
          if (/<\w+[^>]*>/.test(nextLines) && !nextLines.includes("key=")) {
            findings.push({
              id: `react.missing-key:${file}:${i + 1}`,
              category: "security",
              severity: "medium",
              title: "Missing 'key' Prop in List",
              description: "List items rendered without key prop may cause state corruption",
              file,
              line: i + 1,
              framework: "react",
              remediation: "Add unique key prop to list items:\n- Use unique IDs from data: key={item.id}\n- Never use array index as key\n- Keys help React identify which items have changed\n- Prevents state bugs in list items",
              confidence: 0.7
            });
            break;
          }
        }
      }
    }

    // Check for unsafe event handlers
    if (/on\w+\s*=\s*\{.*eval/.test(content)) {
      const line = content.split("\n").findIndex(l => /eval/.test(l)) + 1;
      findings.push({
        id: `react.eval-event:${file}:${line}`,
        category: "security",
        severity: "critical",
        title: "eval() Used in Event Handler",
        description: "Event handler uses eval() which can execute arbitrary code",
        file,
        line,
        framework: "react",
        remediation: "Remove eval() from event handlers:\n- Use direct function calls instead\n- Pass data as props or context\n- Use useCallback hook for handler functions\n- Bind methods in constructor or use arrow functions",
        confidence: 0.95
      });
    }

    // Check for inline event handlers with user data
    if (/on\w+\s*=\s*\{[^}]*\$\{/.test(content)) {
      const line = content.split("\n").findIndex(l => /on\w+\s*=\s*\{[^}]*\$\{/.test(l)) + 1;
      findings.push({
        id: `react.inline-handler:${file}:${line}`,
        category: "security",
        severity: "high",
        title: "Inline Event Handler with Template Literal",
        description: "Event handler uses template literals which can be vulnerable to injection",
        file,
        line,
        framework: "react",
        remediation: "Use proper event handler patterns:\n- Define handlers as separate functions\n- Use useCallback for optimized handlers\n- Pass data through props, not in handler string\n- Example: onClick={() => handleClick(id)} instead of onClick={`doSomething('${id}')`}",
        confidence: 0.65
      });
    }

    // Check for localStorage without encryption
    if (/localStorage\.setItem/.test(content)) {
      if (!/encrypt|crypto|cipher/.test(content)) {
        const line = content.split("\n").findIndex(l => /localStorage\.setItem/.test(l)) + 1;
        findings.push({
          id: `react.unencrypted-storage:${file}:${line}`,
          category: "security",
          severity: "high",
          title: "Unencrypted Data Stored in localStorage",
          description: "Sensitive data stored in localStorage without encryption",
          file,
          line,
          framework: "react",
          remediation: "Encrypt sensitive data before storing:\n- Use crypto-js for client-side encryption\n- Store tokens in secure httpOnly cookies instead\n- Never store passwords or sensitive keys in localStorage\n- Use sessionStorage for session-only data",
          confidence: 0.7
        });
      }
    }
  }

  return findings;
}

/**
 * Scan React Native and iOS specific security issues
 */
export function scanReactNativeIosSecurity(root: string, files: string[]): FrameworkSecurityIssue[] {
  const findings: FrameworkSecurityIssue[] = [];

  // Check for iOS-specific issues
  for (const file of files) {
    if (!file.endsWith(".swift") && !file.endsWith(".m") && !file.endsWith(".h")) continue;
    
    const filePath = path.join(root, file);
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }

    // Check for hardcoded credentials in Swift
    if (/let\s+\w*(key|password|secret|token)\s*=\s*["'][^"']+["']/i.test(content)) {
      const line = content.split("\n").findIndex(l => /let\s+\w*(key|password|secret|token)/.test(l)) + 1;
      findings.push({
        id: `ios.hardcoded-secret:${file}:${line}`,
        category: "security",
        severity: "critical",
        title: "Hardcoded Credentials in Swift Code",
        description: "Secret, key, or token hardcoded in source code",
        file,
        line,
        framework: "ios",
        remediation: "Move credentials to secure storage:\n- Use iOS Keychain for sensitive data\n- Use UserDefaults with proper protection\n- Load from configuration files not in bundle\n- Use environment variables at build time",
        confidence: 0.95
      });
    }

    // Check for unsafe URL handling
    if (/NSURLConnection|URLSession.*credentials/.test(content) && !/.certificatePinning|trustpolicy/.test(content)) {
      const line = content.split("\n").findIndex(l => /NSURLConnection|URLSession/.test(l)) + 1;
      findings.push({
        id: `ios.no-certificate-pinning:${file}:${line}`,
        category: "security",
        severity: "high",
        title: "Missing Certificate Pinning",
        description: "Network requests without certificate pinning are vulnerable to MITM attacks",
        file,
        line,
        framework: "ios",
        remediation: "Implement certificate pinning:\n- Use Alamofire with certificate pinning\n- Implement URLSessionDelegate with pinning\n- Validate server certificates\n- Use TrustKit for certificate pinning",
        confidence: 0.75
      });
    }

    // Check for insecure data storage
    if (/UserDefaults\.standard\.set.*as String|plist.*writeTo/i.test(content)) {
      if (!content.includes("Keychain")) {
        const line = content.split("\n").findIndex(l => /UserDefaults|plist/.test(l)) + 1;
        findings.push({
          id: `ios.insecure-storage:${file}:${line}`,
          category: "security",
          severity: "high",
          title: "Insecure Data Storage (UserDefaults/Plist)",
          description: "Sensitive data stored in UserDefaults or plist files without encryption",
          file,
          line,
          framework: "ios",
          remediation: "Use secure storage mechanisms:\n- Use iOS Keychain for sensitive data\n- Encrypt data with CommonCrypto before storage\n- Use SecureEnclave for critical keys\n- Avoid UserDefaults for sensitive information",
          confidence: 0.85
        });
      }
    }
  }

  // Check for React Native specific issues
  for (const file of files) {
    if (!file.endsWith(".js") && !file.endsWith(".jsx") && !file.endsWith(".ts") && !file.endsWith(".tsx")) continue;
    if (!file.includes("react-native")) continue;
    
    const filePath = path.join(root, file);
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }

    // Check for insecure HTTP usage in React Native
    if (/http:\/\/(?!localhost|127\.0\.0\.1|192\.168)/.test(content)) {
      const line = content.split("\n").findIndex(l => /http:\/\//.test(l)) + 1;
      findings.push({
        id: `rn.insecure-http:${file}:${line}`,
        category: "security",
        severity: "high",
        title: "Insecure HTTP Connection",
        description: "React Native app communicates with remote server over unencrypted HTTP",
        file,
        line,
        framework: "react-native",
        remediation: "Use HTTPS for all network requests:\n- Update API endpoints to HTTPS\n- Configure network security config on Android\n- Use react-native-config for environment-based URLs\n- Enable Certificate Pinning",
        confidence: 0.85
      });
    }

    // Check for missing permission declarations
    if (/require.*native-module|NativeModules\./.test(content)) {
      if (!fs.existsSync(path.join(root, "android", "app", "src", "main", "AndroidManifest.xml")) &&
          !fs.existsSync(path.join(root, "ios", "Info.plist"))) {
        findings.push({
          id: `rn.missing-permissions:${file}`,
          category: "security",
          severity: "high",
          title: "Missing Permission Declarations",
          description: "Native module used without documented permission declarations",
          file,
          framework: "react-native",
          remediation: "Declare all required permissions:\n- Add permissions to AndroidManifest.xml\n- Add NSLocationWhenInUseUsageDescription to Info.plist\n- Document why each permission is needed\n- Request permissions at runtime on Android 6+",
          confidence: 0.65
        });
      }
    }

    // Check for unsafe AsyncStorage usage
    if (/@react-native-async-storage|AsyncStorage\.setItem/.test(content)) {
      if (/password|secret|token|key/i.test(content) && !content.includes("encrypt")) {
        const line = content.split("\n").findIndex(l => /AsyncStorage\.setItem/.test(l)) + 1;
        findings.push({
          id: `rn.unencrypted-async-storage:${file}:${line}`,
          category: "security",
          severity: "high",
          title: "Unencrypted Sensitive Data in AsyncStorage",
          description: "Sensitive data stored in AsyncStorage without encryption",
          file,
          line,
          framework: "react-native",
          remediation: "Encrypt sensitive data before storing:\n- Use react-native-keychain for secure storage\n- Use @react-native-encrypted-storage\n- Implement encryption wrapper for AsyncStorage\n- Store only non-sensitive data",
          confidence: 0.8
        });
      }
    }
  }

  return findings;
}

/**
 * Scan Node.js/Express specific security issues
 */
export function scanNodeJsSecurity(root: string, files: string[]): FrameworkSecurityIssue[] {
  const findings: FrameworkSecurityIssue[] = [];

  for (const file of files) {
    if (!file.endsWith(".js") && !file.endsWith(".ts")) continue;
    
    const filePath = path.join(root, file);
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }

    // Check for missing input validation in Express routes
    if (/\.get|\.post|\.put|\.delete/.test(content) && /req\.body|req\.query|req\.params/.test(content)) {
      if (!content.includes("validate") && !content.includes("check") && !content.includes("joi")) {
        const line = content.split("\n").findIndex(l => /\.get|\.post|\.put|\.delete/.test(l)) + 1;
        findings.push({
          id: `node.missing-validation:${file}:${line}`,
          category: "security",
          severity: "high",
          title: "Missing Input Validation in Route Handler",
          description: "Request parameters used without validation",
          file,
          line,
          framework: "express",
          remediation: "Add input validation to all routes:\n- Use express-validator middleware\n- Use joi for schema validation\n- Check input types and lengths\n- Sanitize user input\n- Whitelist allowed values",
          confidence: 0.6
        });
      }
    }

    // Check for missing rate limiting
    if ((/app\.post|app\.get/i.test(content) || /router\.post|router\.get/i.test(content)) && !file.includes("test")) {
      if (!content.includes("rate") && !content.includes("limit") && !content.includes("throttle")) {
        findings.push({
          id: `node.missing-rate-limit:${file}`,
          category: "security",
          severity: "high",
          title: "Missing Rate Limiting on Routes",
          description: "API routes not protected against brute force or DoS attacks",
          file,
          framework: "express",
          remediation: "Implement rate limiting:\n- Use express-rate-limit middleware\n- Limit requests per IP/user\n- Set appropriate rate limits per endpoint\n- Return 429 status on limit exceeded\n- Monitor and adjust limits based on usage",
          confidence: 0.65
        });
      }
    }

    // Check for missing security headers
    if (/app\.use|middleware/.test(content) && !content.includes("helmet")) {
      if (!/csp|x-frame-options|x-content-type-options/i.test(content)) {
        findings.push({
          id: `node.missing-security-headers:${file}`,
          category: "security",
          severity: "medium",
          title: "Missing Security Headers Middleware",
          description: "Application doesn't set security headers (CSP, X-Frame-Options, etc.)",
          file,
          framework: "express",
          remediation: "Add security headers middleware:\n- Install and use helmet.js\n- Set Content-Security-Policy header\n- Set X-Frame-Options: DENY\n- Set X-Content-Type-Options: nosniff\n- Set Strict-Transport-Security header",
          confidence: 0.7
        });
      }
    }

    // Check for SQL query construction
    if (/SELECT|INSERT|UPDATE|DELETE/.test(content) && /\+\s*['\"]/.test(content)) {
      const line = content.split("\n").findIndex(l => /SELECT|INSERT|UPDATE|DELETE/.test(l)) + 1;
      findings.push({
        id: `node.sql-concat:${file}:${line}`,
        category: "security",
        severity: "critical",
        title: "SQL Query Built with String Concatenation",
        description: "SQL query constructed by concatenating strings, vulnerable to injection",
        file,
        line,
        framework: "express",
        remediation: "Use parameterized queries:\n- Use prepared statements\n- Use ORM libraries (Sequelize, TypeORM, Prisma)\n- Use parameterized query functions: db.query('SELECT * WHERE id = ?', [id])\n- Never concatenate user input directly",
        confidence: 0.85
      });
    }

    // Check for missing CORS configuration
    if (/cors/i.test(content) && content.includes("origin")) {
      if (/origin\s*:\s*['"]\*['"]|origin\s*:\s*true/.test(content)) {
        const line = content.split("\n").findIndex(l => /origin\s*:/.test(l)) + 1;
        findings.push({
          id: `node.cors-wildcard:${file}:${line}`,
          category: "security",
          severity: "high",
          title: "CORS Allows All Origins",
          description: "CORS configured to accept requests from any origin (*)",
          file,
          line,
          framework: "express",
          remediation: "Restrict CORS to trusted origins:\n- List allowed origins explicitly\n- Use environment variables for origin list\n- Never use '*' in production\n- Example: { origin: ['https://app.example.com'] }",
          confidence: 0.9
        });
      }
    }
  }

  return findings;
}
