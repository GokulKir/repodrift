/**
 * Example Security Issues Found by RepoDrift Framework Scanner
 * 
 * This file demonstrates the types of security findings RepoDrift detects
 * across different frameworks and technologies.
 */

// ============================================================================
// NEXT.JS EXAMPLES
// ============================================================================

// ❌ Issue: Unprotected API Route
export async function POST(request) {
  const data = request.body;
  // No authentication check! Anyone can POST here.
  await database.insert(data);
  return Response.json({ success: true });
}

// ❌ Issue: Exposed Environment Variables in Client Code
export async function ClientComponent() {
  const apiKey = process.env.DATABASE_URL; // This is exposed to browser!
  const response = await fetch('http://api.example.com', {
    headers: { 'Authorization': apiKey }
  });
}

// ============================================================================
// REACT.JS EXAMPLES
// ============================================================================

// ❌ Issue: XSS via dangerouslySetInnerHTML
export function BlogPost({ htmlContent }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
  );
  // User-supplied HTML can execute JavaScript!
}

// ❌ Issue: Missing Key Prop in List
export function UserList({ users }) {
  return (
    <ul>
      {users.map((user, index) => (
        <li key={index}>{user.name}</li>
        // Using index as key causes bugs when list changes
      ))}
    </ul>
  );
}

// ❌ Issue: Unencrypted localStorage
export function LoginComponent() {
  const token = localStorage.getItem('auth_token');
  // Token is plaintext! Any script can read it.
}

// ============================================================================
// REACT NATIVE EXAMPLES
// ============================================================================

// ❌ Issue: Unencrypted AsyncStorage
import AsyncStorage from '@react-native-async-storage/async-storage';

export async function saveUserPassword(password) {
  await AsyncStorage.setItem('password', password);
  // Stored in plaintext! Accessible to other apps.
}

// ❌ Issue: Insecure HTTP Connection
export function fetchUserData() {
  fetch('http://api.example.com/users')  // Not encrypted!
    .then(response => response.json());
}

// ============================================================================
// iOS EXAMPLES (Swift)
// ============================================================================

// ❌ Issue: Hardcoded API Secret
let apiSecret = "sk_live_1234567890abcdefghij"
let url = "https://api.example.com?secret=\(apiSecret)"

// ❌ Issue: Insecure UserDefaults
UserDefaults.standard.set(password, forKey: "password")
// Stored in plaintext, accessible to other apps!

// ❌ Issue: No Certificate Pinning
let url = URL(string: "https://api.example.com")!
var request = URLRequest(url: url)
let session = URLSession.shared
// No certificate validation! Vulnerable to MITM attacks.

// ============================================================================
// NODE.JS / EXPRESS EXAMPLES
// ============================================================================

// ❌ Issue: Missing Input Validation
app.post('/users/:id', (req, res) => {
  const id = req.params.id;
  // No validation! Could be any value.
  const user = db.findById(id);
  res.json(user);
});

// ❌ Issue: SQL Injection via String Concatenation
app.get('/search', (req, res) => {
  const query = req.query.q;
  // String concatenation = SQL injection vulnerability!
  const results = db.query(`SELECT * FROM posts WHERE title LIKE '%${query}%'`);
  res.json(results);
});

// ❌ Issue: Missing Rate Limiting
app.post('/login', (req, res) => {
  // No rate limiting! Vulnerable to brute force attacks.
  const user = authenticate(req.body.email, req.body.password);
  res.json(user);
});

// ❌ Issue: CORS Allows All Origins
app.use(cors({ origin: '*' }));
// Any website can call your API! Data exposed.

// ❌ Issue: Missing Security Headers
app.use(express.json());
app.use(express.static('public'));
// No helmet.js! Missing Content-Security-Policy and other headers.

// ============================================================================
// GENERAL JAVASCRIPT EXAMPLES
// ============================================================================

// ❌ Issue: eval() Usage
const userCode = getUserInput();
eval(userCode);  // User can execute arbitrary code!

// ❌ Issue: Command Injection
const filename = req.query.file;
exec(`cat ${filename}`);  // Command injection vulnerability!

// ❌ Issue: Weak Randomness for Security
const sessionId = Math.random().toString(36);
// Math.random() is predictable! Use crypto.randomBytes()

// ❌ Issue: Hardcoded Credentials
const mongoUrl = 'mongodb://user:password123@db.example.com';
// Credentials visible in source control!
const apiKey = 'sk_test_abc123xyz789';
// API keys should never be in code!

// ============================================================================
// WHAT REPODRIFT DETECTS
// ============================================================================

/*
SEVERITY LEVELS:
- 🔴 CRITICAL: Immediate security threat (exploit possible)
- 🔴 HIGH: Significant security risk (easily exploited)
- 🟡 MEDIUM: Notable security concern (exploitation requires effort)
- 🔵 LOW: Minor issue or best practice violation

FINDING DETAILS INCLUDE:
✓ Issue title and description
✓ File and line number
✓ Severity and confidence score
✓ Why it matters (security impact)
✓ Step-by-step remediation
✓ Code examples for fixes
✓ Framework-specific guidance

EXAMPLE OUTPUT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL SEVERITY (3 findings)

1. SQL Injection Vulnerability
   Category: security
   File: src/api/search.js:42
   Description: SQL query built with string concatenation
   
   Why it matters:
   Attackers can modify database queries to extract sensitive data,
   modify records, or delete entire tables.
   
   How to fix:
   1. Use parameterized queries: db.query('SELECT * WHERE id = ?', [id])
   2. Use ORM libraries (Sequelize, TypeORM, Prisma)
   3. Never concatenate user input into SQL strings
   
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RUN REPODRIFT:
$ repodrift scan /path/to/project --verbose

Get detailed security analysis with remediation guidance for all frameworks!
*/
