# RepoDrift v0.2.0 - Release Notes

**Published:** September 1, 2026  
**npm Package:** [@repodrift/cli@0.2.0](https://www.npmjs.com/package/@repodrift/cli)  
**Package Size:** 27.0 kB (unpacked: 98.7 kB)

## 🎉 Major Features Added

### 1. Framework-Specific Security Scanning
RepoDrift now auto-detects and applies framework-specific security checks for:
- **Next.js** (5 checks) - API routes, environment variables, CSRF protection
- **React.js** (5 checks) - XSS vulnerabilities, state management, storage
- **React Native** (3 checks) - Mobile security, encryption, permissions
- **iOS** (3 checks) - Keychain usage, certificates, data storage
- **Node.js/Express** (5 checks) - Input validation, rate limiting, CORS
- **Android** - Permission declarations and configuration
- **NestJS** - Framework-specific validation

### 2. Enhanced Terminal Output
- ✨ **ASCII Art Banner** - Large RepoDrift logo displayed at scan start
- 🎨 **Animated Spinner** - Dynamic loading indicator during scans
- 🔴 **Color-Coded Findings** - Organized by severity with emoji icons
- 📊 **Detailed Remediation** - Step-by-step fixes with code examples
- 📈 **Verbose Mode** - Metrics like LOC, file sizes, git info
- 📋 **JSON Output** - Machine-readable format for CI/CD integration

### 3. Comprehensive Security Checks (50+ patterns)

**Core Security (30+ checks):**
- AWS Access Keys, GitHub Tokens, Stripe Keys (CRITICAL)
- Private Keys, Hardcoded Secrets, Database URLs (CRITICAL)
- eval(), Shell Injection, SQL Injection (CRITICAL)
- XSS, Path Traversal, Code Execution (HIGH)
- Weak Randomness, Insecure Protocols (HIGH)
- Disabled Certificates, Sensitive Logging (CRITICAL)
- ReDoS, Missing Headers, CORS Issues (MEDIUM)

**Framework-Specific (21+ checks):**
- Unprotected API Routes, Exposed Env Vars
- dangerouslySetInnerHTML, Missing Key Props
- Unencrypted Storage (AsyncStorage, localStorage)
- Missing Validation, Rate Limiting, Certificate Pinning
- And more...

## 📦 Package Contents

```
@repodrift/cli@0.2.0
├── bin/repodrift                    (CLI executable)
├── dist/
│   ├── index.js                     (Main entry point)
│   ├── core/
│   │   ├── security.ts              (30+ security rules)
│   │   ├── framework-security.ts    (Framework detection & scanning)
│   │   ├── engine.ts                (Integrated analysis)
│   │   └── ... (other modules)
│   └── ... (more compiled files)
├── docs/FRAMEWORK_SECURITY_GUIDE.md (Comprehensive guide)
├── examples/SECURITY_FINDINGS_EXAMPLES.ts (Example vulnerabilities)
└── LICENSE, README.md               (Documentation)
```

## 🚀 Installation & Usage

### Install Globally
```bash
npm install -g @repodrift/cli@0.2.0
repodrift scan /path/to/project
```

### Install Locally
```bash
npm install --save-dev @repodrift/cli@0.2.0
npx repodrift scan .
```

### Usage Examples
```bash
# Standard scan with auto-framework detection
repodrift scan

# Verbose output with metrics
repodrift scan --verbose

# JSON output for CI/CD
repodrift scan --json > report.json

# Exit on critical findings
repodrift scan --fail-on critical
```

## 📊 What's New in v0.2.0

| Feature | v0.1.6 | v0.2.0 |
|---------|--------|--------|
| Security Checks | 8 | 50+ |
| Framework Support | General | 7 Frameworks |
| Terminal Output | Basic | Enhanced with Banner |
| Remediation Detail | Brief | Complete with Examples |
| Framework Detection | Manual | Auto-Detection |
| JSON Output | ✓ | ✓ |
| Verbose Mode | ✗ | ✓ |

## 🔧 Breaking Changes

**None!** This release is backward compatible with v0.1.6. All existing commands work exactly the same, with enhanced output and additional checks.

## 📝 Migration Guide

Existing users will automatically benefit from:
1. **More findings** - 50+ checks instead of 8
2. **Better output** - Enhanced terminal display with banner and colors
3. **Framework guidance** - Specific fixes for your tech stack
4. **Same API** - No command changes needed

Just update and run your existing commands:
```bash
npm update @repodrift/cli
repodrift scan  # Works exactly the same, but better!
```

## 🛠️ CI/CD Integration

Add to your GitHub Actions workflow:
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install @repodrift/cli@0.2.0
      - run: npx repodrift scan . --json > report.json
      - run: |
          CRITICAL=$(jq '[.findings[] | select(.severity=="critical")] | length' report.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Critical issues found!"
            exit 1
          fi
```

## 📖 Documentation

- **Security Guide:** See `docs/FRAMEWORK_SECURITY_GUIDE.md` for comprehensive guide
- **Examples:** See `examples/SECURITY_FINDINGS_EXAMPLES.ts` for real-world vulnerabilities
- **README:** Full documentation at [GitHub](https://github.com/yourusername/repodrift)

## 🐛 Bug Fixes

- Fixed false positives in path traversal detection
- Improved regex performance for large files
- Better handling of binary files

## 🎯 Upcoming Features (v0.3.0+)

- [ ] Custom security rules configuration
- [ ] Integration with GitHub Security tab
- [ ] Trend analysis and history tracking
- [ ] AI-powered recommendations
- [ ] Docker container scanning
- [ ] Infrastructure-as-Code (Terraform, CloudFormation)
- [ ] Compliance checks (GDPR, HIPAA, SOC2)

## 📞 Support

- **Report Issues:** [GitHub Issues](https://github.com/yourusername/repodrift/issues)
- **Documentation:** [GitHub Wiki](https://github.com/yourusername/repodrift/wiki)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/repodrift/discussions)

## 📄 License

MIT License - See LICENSE file for details

---

**Published by:** infy2003 <whisprgeo@gmail.com>  
**Package:** https://www.npmjs.com/package/@repodrift/cli  
**Repository:** https://github.com/yourusername/repodrift
