# RepoDrift Framework-Specific Security Scanning Guide

## Overview
RepoDrift now provides comprehensive security scanning for:
- **Next.js** - Full-stack React framework
- **React.js** - UI component library
- **React Native** - Mobile development framework  
- **iOS** - Native Apple development
- **Node.js/Express** - Backend server frameworks
- **Android** - Native Android development

## Framework Detection

RepoDrift automatically detects your project's frameworks by analyzing:
- `package.json` dependencies
- Directory structures (e.g., `ios/`, `android/`)
- Configuration files

Example output:
```
Detected frameworks:
✓ React (v18.2.0)
✓ Express (v4.18.2)
✓ TypeScript (v5.0.0)
```

## Next.js Security Checks

### 1. Unprotected API Routes
**Severity:** HIGH
**Issue:** API routes lack authentication/authorization checks
**Example Finding:**
```typescript
// ❌ INSECURE: No authentication
export async function POST(req) {
  const data = req.body;
  await db.save(data);  // Any user can modify data!
  return NextResponse.json({ success: true });
}
```

**Fix:**
```typescript
// ✓ SECURE: With authentication
import { auth } from '@/lib/auth';

export async function POST(req) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });
  
  const data = req.body;
  await db.save(data);
  return NextResponse.json({ success: true });
}
```

### 2. Exposed Environment Variables
**Severity:** HIGH
**Issue:** Sensitive environment variables accessed in client-side code
**Example Finding:**
```typescript
// ❌ INSECURE: Client can see database credentials
const dbUrl = process.env.DATABASE_URL;  // Exposed to browser!
const data = await fetch('http://api.com', {
  headers: { 'X-DB-URL': dbUrl }
});
```

**Fix:**
```typescript
// ✓ SECURE: Server-side only
export async function getServerSideProps() {
  const dbUrl = process.env.DATABASE_URL;
  const data = await db.query(dbUrl);
  return { props: { data } };
}

// ✓ SECURE: Or use NEXT_PUBLIC_ for public vars only
const apiKey = process.env.NEXT_PUBLIC_API_KEY;  // OK for client
```

### 3. Missing CSRF Protection
**Severity:** HIGH
**Issue:** State-changing operations (POST/PUT/DELETE) lack CSRF tokens
**Fix:** Install next-csrf or validate tokens on all mutating endpoints

## React Security Checks

### 1. XSS via dangerouslySetInnerHTML
**Severity:** HIGH
**Issue:** Bypasses React's built-in XSS protection
**Example Finding:**
```jsx
// ❌ INSECURE: User content can execute JavaScript
export function Comment({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
```

**Fix:**
```jsx
import DOMPurify from 'dompurify';

// ✓ SECURE: Sanitize before rendering
export function Comment({ content }) {
  const sanitized = DOMPurify.sanitize(content);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// Or better: Just use plain JSX
export function Comment({ content }) {
  return <div>{content}</div>;  // Auto-escaped!
}
```

### 2. Missing Key Props in Lists
**Severity:** MEDIUM
**Issue:** Can cause state bugs when list items are reordered
**Example Finding:**
```jsx
// ❌ INSECURE: No keys or using index as key
{items.map((item, index) => (
  <Item key={index} data={item} />  // Bad: index unstable
))}
```

**Fix:**
```jsx
// ✓ SECURE: Use stable unique keys
{items.map((item) => (
  <Item key={item.id} data={item} />  // Unique ID
))}
```

### 3. Unencrypted localStorage
**Severity:** HIGH  
**Issue:** Sensitive data stored in plaintext localStorage
**Example Finding:**
```javascript
// ❌ INSECURE: Tokens visible to any script on the page
localStorage.setItem('auth_token', token);
```

**Fix:**
```javascript
import * as SecureLS from 'secure-ls';

// ✓ SECURE: Encrypt before storing
const ls = new SecureLS();
ls.set('auth_token', token);

// Or better: Use secure httpOnly cookies via backend
// Cookies are inaccessible to JavaScript!
```

## React Native & iOS Security Checks

### 1. Hardcoded Secrets in Code
**Severity:** CRITICAL
**Issue:** API keys, tokens, or passwords visible in source
**Example Finding (Swift):**
```swift
// ❌ INSECURE: Secret visible in binary!
let apiKey = "sk_live_51234567890abcdef"
let url = URL(string: "https://api.example.com/v1/data?key=\(apiKey)")!
```

**Fix:**
```swift
// ✓ SECURE: Load from iOS Keychain at runtime
import Security

func getAPIKey() -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "api_key",
    kSecReturnData as String: kCFBooleanTrue!
  ]
  var result: AnyObject?
  SecItemCopyMatching(query as CFDictionary, &result)
  guard let data = result as? Data else { return nil }
  return String(data: data, encoding: .utf8)
}
```

### 2. Insecure HTTP Connections
**Severity:** HIGH
**Issue:** Unencrypted network communication
**Example Finding:**
```javascript
// ❌ INSECURE: Man-in-the-middle attack possible
fetch('http://api.example.com/users')  // Not encrypted!
```

**Fix:**
```javascript
// ✓ SECURE: Always use HTTPS
fetch('https://api.example.com/users', {
  headers: { Authorization: `Bearer ${token}` }
});

// Enable certificate pinning for extra security
// Use TrustKit or similar
```

### 3. Missing Certificate Pinning (iOS)
**Severity:** HIGH
**Issue:** Vulnerable to man-in-the-middle attacks
**Fix:**
```swift
// ✓ SECURE: Use certificate pinning
import Alamofire

let certificates = [SecCertificate]()
let certificatePinning = CertificatePinning(certificates: certificates)
let manager = Session(evaluators: [
  "api.example.com": PinnedCertificatesTrustEvaluator()
])
```

### 4. Insecure AsyncStorage (React Native)
**Severity:** HIGH
**Issue:** Sensitive data stored in plaintext AsyncStorage
**Example Finding:**
```javascript
// ❌ INSECURE: Password visible in storage
AsyncStorage.setItem('password', userPassword);
```

**Fix:**
```javascript
import * as Keychain from 'react-native-keychain';

// ✓ SECURE: Use Keychain for sensitive data
await Keychain.setGenericPassword('username', userPassword);

// For non-sensitive data only
AsyncStorage.setItem('preferences', JSON.stringify(settings));
```

## Node.js/Express Security Checks

### 1. Missing Input Validation
**Severity:** HIGH
**Issue:** Request parameters used without validation
**Example Finding:**
```javascript
// ❌ INSECURE: No validation
app.post('/users/:id', (req, res) => {
  const user = db.find(req.params.id);  // ID could be malicious
  res.json(user);
});
```

**Fix:**
```javascript
import { check, validationResult } from 'express-validator';

// ✓ SECURE: Validate input
app.post('/users/:id',
  check('id').isInt().positive(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const user = db.find(req.params.id);
    res.json(user);
  }
);
```

### 2. SQL Injection via String Concatenation
**Severity:** CRITICAL
**Issue:** SQL queries built by concatenating user input
**Example Finding:**
```javascript
// ❌ INSECURE: SQL injection vulnerability!
const id = req.params.id;
db.query(`SELECT * FROM users WHERE id = ${id}`);  // Hacked!
```

**Fix:**
```javascript
// ✓ SECURE: Use parameterized queries
db.query('SELECT * FROM users WHERE id = ?', [id]);

// Or with an ORM:
const user = await User.findById(id);  // Type-safe!
```

### 3. Missing Rate Limiting
**Severity:** HIGH
**Issue:** Vulnerable to brute force and DoS attacks
**Example Finding:**
```javascript
// ❌ INSECURE: No rate limiting
app.post('/login', (req, res) => {
  const user = authenticate(req.body);  // Brute force!
  res.json(user);
});
```

**Fix:**
```javascript
import rateLimit from 'express-rate-limit';

// ✓ SECURE: Limit login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // 5 requests per window
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, (req, res) => {
  const user = authenticate(req.body);
  res.json(user);
});
```

### 4. CORS Allowing All Origins
**Severity:** HIGH
**Issue:** CORS misconfigured to accept requests from any origin
**Example Finding:**
```javascript
// ❌ INSECURE: Allows any website to call your API
app.use(cors({ origin: '*' }));
```

**Fix:**
```javascript
// ✓ SECURE: Whitelist trusted origins
app.use(cors({
  origin: ['https://myapp.com', 'https://www.myapp.com'],
  credentials: true
}));
```

### 5. Missing Security Headers
**Severity:** MEDIUM
**Issue:** Application doesn't set security headers
**Fix:**
```javascript
import helmet from 'helmet';

// ✓ SECURE: Add security headers
app.use(helmet());

// Helmet sets:
// - Content-Security-Policy
// - X-Frame-Options: DENY
// - X-Content-Type-Options: nosniff
// - Strict-Transport-Security
```

## Running Framework-Specific Scans

```bash
# Scan with framework detection and checks
repodrift scan /path/to/project

# Get JSON output for CI/CD
repodrift scan /path/to/project --json

# Verbose output with detected frameworks
repodrift scan /path/to/project --verbose
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install @repodrift/cli
      - run: npx repodrift scan . --json > results.json
      - run: |
          CRITICAL=$(jq '.findings[] | select(.severity=="critical") | length' results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found critical security issues!"
            exit 1
          fi
```

## Best Practices Summary

### All Frameworks
✓ Never hardcode secrets - use environment variables or secret managers
✓ Validate and sanitize all user input
✓ Use HTTPS for all network communication
✓ Implement proper authentication and authorization
✓ Add rate limiting to sensitive endpoints
✓ Keep dependencies up to date
✓ Use security headers
✓ Log security events

### Frontend (React, React Native)
✓ Sanitize HTML before rendering
✓ Use unique, stable keys for lists
✓ Avoid eval() and dangerouslySetInnerHTML
✓ Encrypt sensitive data in storage
✓ Validate JWT tokens
✓ Implement CSRF protection

### Backend (Node.js, Express, Next.js)
✓ Validate all inputs server-side
✓ Use parameterized queries
✓ Implement rate limiting
✓ Add CORS restrictions
✓ Use secure session management
✓ Implement proper error handling
✓ Log access attempts

### Mobile (React Native, iOS)
✓ Use Keychain for sensitive data (iOS)
✓ Implement certificate pinning
✓ Encrypt local databases
✓ Request permissions explicitly
✓ Validate server certificates
✓ Protect sensitive APIs with authentication
