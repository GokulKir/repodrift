import fs from "node:fs";
import path from "node:path";

export type MobilePlatform = "android" | "ios" | "unknown";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface MobileFinding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  remediation: string;
  confidence: number;
}

export interface MobileCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
}

export interface MobileHealthReport {
  platform: MobilePlatform;
  framework: string;
  score: number;
  grade: string;
  checks: MobileCheck[];
  findings: MobileFinding[];
}

const ANDROID_DANGEROUS_PERMISSIONS = new Set([
  "READ_SMS",
  "SEND_SMS",
  "CALL_PHONE",
  "READ_CALL_LOG",
  "READ_CONTACTS",
  "WRITE_CONTACTS",
  "ACCESS_FINE_LOCATION",
  "ACCESS_COARSE_LOCATION",
  "CAMERA",
  "RECORD_AUDIO",
  "READ_EXTERNAL_STORAGE",
  "WRITE_EXTERNAL_STORAGE",
  "POST_NOTIFICATIONS"
]);

export function scanMobileHealth(root: string): MobileHealthReport {
  const resolvedRoot = path.resolve(root);
  const androidDetected = hasAndroidProject(resolvedRoot);
  const iosDetected = hasIOSProject(resolvedRoot);
  const platform: MobilePlatform = androidDetected ? "android" : iosDetected ? "ios" : "unknown";
  const framework = detectFramework(resolvedRoot, platform);

  if (platform === "android") return scanAndroidHealth(resolvedRoot, framework);
  if (platform === "ios") return scanIOSHealth(resolvedRoot, framework);

  return {
    platform: "unknown",
    framework: "Unknown",
    score: 0,
    grade: "F",
    checks: [{ name: "Project detection", status: "fail", detail: "No Android or iOS project files were detected." }],
    findings: [{
      id: "mobile.project-unknown",
      severity: "info",
      title: "Could not detect a mobile project",
      description: "RepoDrift did not find an Android or iOS app structure in this directory.",
      remediation: "Run the scan in a folder containing Android or iOS project files such as Gradle or Xcode metadata.",
      confidence: 1,
    }],
  };
}

function scanAndroidHealth(root: string, framework: string): MobileHealthReport {
  const manifestPath = findFile(root, [
    "android/app/src/main/AndroidManifest.xml",
    "android/src/main/AndroidManifest.xml",
    "AndroidManifest.xml"
  ]);
  const buildGradlePath = findFile(root, [
    "android/app/build.gradle",
    "android/build.gradle",
    "build.gradle"
  ]);
  const gradlePropertiesPath = findFile(root, [
    "android/gradle.properties",
    "gradle.properties"
  ]);

  const gradleText = readText(buildGradlePath ?? root);
  const manifestText = readText(manifestPath ?? root);
  const gradlePropertiesText = readText(gradlePropertiesPath ?? root);

  const compileSdk = extractNumber(gradleText, /compileSdk\s+(\d+)/);
  const targetSdk = extractNumber(gradleText, /targetSdk\s+(\d+)/);
  const minSdk = extractNumber(gradleText, /minSdk\s+(\d+)/);
  const agpVersion = extractString(gradleText, /com\.android\.tools\.build:gradle:(\d+\.\d+\.\d+)/) ?? "unknown";
  const kotlinVersion = extractString(gradleText, /kotlin_version\s*=\s*["']?([^\s"']+)/) ?? extractString(gradleText, /kotlin\s*\("([^\)]+)"\)/);

  const checks: MobileCheck[] = [];
  const findings: MobileFinding[] = [];

  if (compileSdk && compileSdk >= 34) {
    checks.push({ name: "Gradle configuration", status: "pass", detail: `compileSdk ${compileSdk} is aligned with modern Android builds.` });
  } else {
    checks.push({ name: "Gradle configuration", status: "warn", detail: `compileSdk is ${compileSdk ?? "missing"}; validate it against supported Android API levels.` });
  }

  if (targetSdk && targetSdk >= 33) {
    checks.push({ name: "Target SDK", status: "pass", detail: `targetSdk ${targetSdk} is current.` });
  } else {
    checks.push({ name: "Target SDK", status: "warn", detail: `targetSdk ${targetSdk ?? "missing"}; align with the latest Android release window.` });
  }

  if (manifestText.includes("android:debuggable=\"true\"") || manifestText.includes("debuggable true") || gradlePropertiesText.includes("android.injected.invoked.from.ide=true")) {
    findings.push({
      id: "android.debuggable-release",
      severity: "high",
      title: "Debuggable release configuration",
      description: "A release manifest or default build setup still exposes debug flags, which can leak runtime internals in production builds.",
      file: manifestPath ?? "AndroidManifest.xml",
      remediation: "Set android:debuggable=false in the release configuration and enforce signing with release build types.",
      confidence: 0.93,
    });
    checks.push({ name: "Debug configuration", status: "fail", detail: "Debug flags are enabled in the app configuration." });
  } else {
    checks.push({ name: "Debug configuration", status: "pass", detail: "No explicit debug flag was detected in the release manifest." });
  }

  const permissionMatches = [...manifestText.matchAll(/android:name="android\.permission\.([A-Z_]+)"/g)].map((match) => match[1]);
  const dangerousPermissions = permissionMatches.filter((permission) => ANDROID_DANGEROUS_PERMISSIONS.has(permission));
  if (dangerousPermissions.length) {
    findings.push({
      id: "android.dangerous-permissions",
      severity: "medium",
      title: "Excessive permissions detected",
      description: `The app requests high-risk Android permissions: ${dangerousPermissions.slice(0, 5).join(", ")}.`,
      file: manifestPath ?? "AndroidManifest.xml",
      remediation: "Remove unused permissions and request only the minimum set needed for the feature set.",
      confidence: 0.88,
    });
    checks.push({ name: "Permissions", status: "warn", detail: `${dangerousPermissions.length} potentially risky permissions were found.` });
  } else {
    checks.push({ name: "Permissions", status: "pass", detail: "No dangerous permission set was detected in the manifest." });
  }

  if (/android:exported="true"/i.test(manifestText) || /android:exported="true"/i.test(gradleText)) {
    const exportedComponents = [...manifestText.matchAll(/<(activity|service|receiver)\b[^>]*android:exported="true"[^>]*>/gi)];
    if (exportedComponents.length) {
      findings.push({
        id: "android.exported-components",
        severity: "medium",
        title: "Exported Android components",
        description: `The manifest exposes ${exportedComponents.length} Android component(s) to other apps. Review whether they require explicit access protection.`,
        file: manifestPath ?? "AndroidManifest.xml",
        remediation: "Restrict exported components to trusted callers and add explicit permission guards when needed.",
        confidence: 0.8,
      });
      checks.push({ name: "Manifest", status: "warn", detail: `${exportedComponents.length} exported component(s) should be reviewed.` });
    }
  } else {
    checks.push({ name: "Manifest", status: "pass", detail: "Manifest exports are not obviously exposed without review." });
  }

  if (kotlinVersion && Number.parseFloat(kotlinVersion) < 1.9) {
    findings.push({
      id: "android.kotlin-version",
      severity: "medium",
      title: "Outdated Kotlin version",
      description: `Kotlin ${kotlinVersion} is older than the currently recommended modern toolchain and may reduce compatibility with the build pipeline.`,
      file: buildGradlePath ?? "android/build.gradle",
      remediation: "Upgrade the Kotlin version in the Gradle build script to a modern release supported by the current Android Gradle Plugin.",
      confidence: 0.75,
    });
  }

  if (agpVersion && Number.parseFloat(agpVersion) < 8.1) {
    findings.push({
      id: "android.agp-version",
      severity: "medium",
      title: "Outdated Android Gradle Plugin",
      description: `AGP ${agpVersion} is several releases behind the current tooling and may miss performance and security fixes.`,
      file: buildGradlePath ?? "android/build.gradle",
      remediation: "Update Android Gradle Plugin and the related Gradle wrapper to a supported modern version.",
      confidence: 0.74,
    });
  }

  if (/api[_-]?key|secret|token|password|google.*map.*key/i.test(manifestText) || /api[_-]?key|secret|token|password/i.test(gradlePropertiesText)) {
    findings.push({
      id: "android.hardcoded-credentials",
      severity: "high",
      title: "Potential hardcoded secret or API key",
      description: "The Android configuration appears to contain credential-like values in source or build files.",
      file: manifestPath ?? gradlePropertiesPath ?? "android",
      remediation: "Move secrets to secure build-time configuration, CI secrets, or platform keystore entries and avoid committing them to source control.",
      confidence: 0.82,
    });
  }

  if (!/signingConfigs|storeFile|keyAlias|storePassword|keyPassword/i.test(gradleText) && !/android:debuggable="true"/i.test(manifestText)) {
    findings.push({
      id: "android.release-signing-missing",
      severity: "high",
      title: "Android release signing config is missing",
      description: "The app does not appear to define a release signing configuration, which can block secure release builds and produce mis-signed artifacts.",
      file: buildGradlePath ?? "android/app/build.gradle",
      remediation: "Define a release signingConfig with storeFile, storePassword, keyAlias, and keyPassword, and enforce it in the release buildType.",
      confidence: 0.9,
    });
    checks.push({ name: "Signing configuration", status: "warn", detail: "No release signing configuration was detected in the Android build files." });
  } else {
    checks.push({ name: "Signing configuration", status: "pass", detail: "Android release signing configuration appears to be defined." });
  }

  if (/android:usesCleartextTraffic="true"|usesCleartextTraffic\s*\)|usesCleartextTraffic\s*=/i.test(manifestText) || /android:allowBackup="true"/i.test(manifestText)) {
    findings.push({
      id: "android.cleartext-traffic",
      severity: "medium",
      title: "Insecure Android networking or backup defaults",
      description: "The manifest enables cleartext HTTP traffic or backup behavior that may broaden the attack surface for release builds.",
      file: manifestPath ?? "AndroidManifest.xml",
      remediation: "Disable cleartext traffic for production builds and review backup settings to ensure only approved data is backed up.",
      confidence: 0.82,
    });
    checks.push({ name: "Network/backup defaults", status: "warn", detail: "Cleartext traffic or backup defaults may be too permissive for production." });
  } else {
    checks.push({ name: "Network/backup defaults", status: "pass", detail: "Network and backup defaults appear aligned with a secure release posture." });
  }

  const dependencySignal = detectDependencySignal(root, framework);
  if (dependencySignal) {
    findings.push(dependencySignal);
    checks.push({ name: "Dependencies", status: "warn", detail: dependencySignal.description });
  } else {
    checks.push({ name: "Dependencies", status: "pass", detail: "Dependency configuration appears current and manageable." });
  }

  const score = calculateScore(findings);
  return {
    platform: "android",
    framework,
    score,
    grade: gradeForScore(score),
    checks,
    findings,
  };
}

function scanIOSHealth(root: string, framework: string): MobileHealthReport {
  const infoPlistPath = findFile(root, [
    "ios/Info.plist",
    "Info.plist",
    "**/Info.plist"
  ]);
  const podfilePath = findFile(root, ["ios/Podfile", "Podfile"]);
  const workspacePath = findFile(root, ["ios/*.xcworkspace", "*.xcworkspace", "ios/*.xcodeproj", "*.xcodeproj"]);
  const packageResolved = findFile(root, ["Package.resolved", "ios/Package.resolved"]);

  const infoPlistText = readText(infoPlistPath ?? root);
  const podfileText = readText(podfilePath ?? root);
  const packageText = readText(packageResolved ?? root);

  const checks: MobileCheck[] = [];
  const findings: MobileFinding[] = [];

  const deploymentTarget = extractString(infoPlistText, /IPHONEOS_DEPLOYMENT_TARGET\s*<\s*string>([^<]+)<\//) ?? extractString(podfileText, /platform\s*:\ios,\s*'([^']+)'/);
  const swiftVersion = extractString(infoPlistText, /SWIFT_VERSION\s*<\s*string>([^<]+)<\//) ?? extractString(podfileText, /swift_version\s*['"]?([^'"\s]+)/);

  if (deploymentTarget && Number.parseFloat(deploymentTarget) >= 15) {
    checks.push({ name: "Build configuration", status: "pass", detail: `iOS deployment target is ${deploymentTarget}.` });
  } else {
    checks.push({ name: "Build configuration", status: "warn", detail: `Deployment target ${deploymentTarget ?? "missing"} should be checked for support expectations.` });
  }

  if (swiftVersion && Number.parseFloat(swiftVersion) >= 5) {
    checks.push({ name: "Swift version", status: "pass", detail: `Swift ${swiftVersion} is supported.` });
  } else {
    checks.push({ name: "Swift version", status: "warn", detail: `Swift version ${swiftVersion ?? "missing"} should be confirmed for compatibility.` });
  }

  if (/NSAllowsArbitraryLoads/i.test(infoPlistText) || /NSExceptionAllowsInsecureHTTPLoads/i.test(infoPlistText)) {
    findings.push({
      id: "ios.ats-insecure",
      severity: "medium",
      title: "ATS configuration permits insecure loads",
      description: "The app allows insecure HTTP or network access, which increases exposure to man-in-the-middle and network downgrade issues.",
      file: infoPlistPath ?? "Info.plist",
      remediation: "Remove arbitrary-load exceptions unless they are absolutely required and restrict them to trusted domains.",
      confidence: 0.9,
    });
    checks.push({ name: "ATS", status: "warn", detail: "App Transport Security is configured to allow insecure connections." });
  } else {
    checks.push({ name: "ATS", status: "pass", detail: "Transport Security appears to be configured in a secure default posture." });
  }

  const usageDescriptions = [
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription"
  ];
  const declaredPermissions = usageDescriptions.filter((key) => infoPlistText.includes(key));
  if (declaredPermissions.length) {
    checks.push({ name: "Permissions", status: "pass", detail: `${declaredPermissions.length} iOS privacy permission entries were declared.` });
  } else {
    checks.push({ name: "Permissions", status: "warn", detail: "No privacy permission declarations were found in the plist metadata." });
  }

  if (podfileText || packageText) {
    checks.push({ name: "Dependencies", status: "pass", detail: "CocoaPods or Swift Package metadata is present for external dependency management." });
  } else {
    checks.push({ name: "Dependencies", status: "warn", detail: "No CocoaPods or package manifest was found; dependency health should be checked manually." });
  }

  if (workspacePath) {
    checks.push({ name: "Signing configuration", status: "pass", detail: "Xcode project metadata was detected; signing and build settings should be reviewed in the Xcode project." });
  } else {
    checks.push({ name: "Signing configuration", status: "warn", detail: "No Xcode workspace metadata was detected; validate entitlements and signing manually." });
  }

  if (/api[_-]?key|secret|token|password/i.test(infoPlistText) || /api[_-]?key|secret|token|password/i.test(podfileText)) {
    findings.push({
      id: "ios.hardcoded-credentials",
      severity: "high",
      title: "Potential hardcoded secret in iOS config",
      description: "Credential-like values may be embedded in the iOS app configuration or project files.",
      file: infoPlistPath ?? podfilePath ?? "ios",
      remediation: "Move credentials to secure environment variables, keychain storage, or CI-managed secrets before shipping.",
      confidence: 0.79,
    });
  }

  if (containsLargeResource(root)) {
    findings.push({
      id: "ios.large-resource",
      severity: "low",
      title: "Large resource detected",
      description: "The project contains a large resource asset that may increase download size and slow install/launch cycles.",
      file: "ios",
      remediation: "Compress or split large media files and review duplicate asset bundles before release.",
      confidence: 0.72,
    });
    checks.push({ name: "Resources", status: "warn", detail: "Large media or bundle assets were detected in the project tree." });
  } else {
    checks.push({ name: "Resources", status: "pass", detail: "No unusually large resources were detected." });
  }

  const score = calculateScore(findings);
  return {
    platform: "ios",
    framework,
    score,
    grade: gradeForScore(score),
    checks,
    findings,
  };
}

function detectDependencySignal(root: string, framework: string): MobileFinding | null {
  const packageJsonPath = path.join(root, "package.json");
  if (fs.existsSync(packageJsonPath)) {
    const packageJson = readText(packageJsonPath);
    const location = /"react-native"\s*:\s*"([^"]+)"/.exec(packageJson);
    if (location && Number.parseFloat(location[1].replace(/[^0-9.]/g, "")) < 0.75) {
      return {
        id: "android.react-native-version",
        severity: "medium",
        title: "Outdated React Native dependency",
        description: `The app is using React Native ${location[1]}, which may miss bug fixes and compatibility updates.`,
        file: "package.json",
        remediation: "Upgrade the React Native dependency to a supported current minor version and validate native build compatibility.",
        confidence: 0.84,
      };
    }
    if (/"react-native"\s*:\s*"[^"]+"/.test(packageJson) && !/"react-native"\s*:\s*"[^"]+"/.test(packageJson)) {
      return null;
    }
  }

  if (framework === "Flutter") {
    return {
      id: "mobile.flutter-check",
      severity: "info",
      title: "Flutter project detected",
      description: "Flutter projects should be reviewed with Flutter-specific build and package rules as part of a mobile health check.",
      file: "pubspec.yaml",
      remediation: "Review package compatibility, build flavors, and signing configuration for the app release pipeline.",
      confidence: 0.5,
    };
  }

  return null;
}

function hasAndroidProject(root: string): boolean {
  return fs.existsSync(path.join(root, "android")) || fs.existsSync(path.join(root, "android", "app", "src", "main", "AndroidManifest.xml")) || findFile(root, [
    "android/**/AndroidManifest.xml",
    "**/AndroidManifest.xml"
  ]) !== null;
}

function hasIOSProject(root: string): boolean {
  return fs.existsSync(path.join(root, "ios")) || fs.existsSync(path.join(root, "Podfile")) || findFile(root, [
    "**/*.xcodeproj",
    "**/*.xcworkspace",
    "**/Info.plist"
  ]) !== null;
}

function detectFramework(root: string, platform: MobilePlatform): string {
  const packageText = readText(path.join(root, "package.json"));
  if (packageText.includes('"react-native"') || packageText.includes('"expo"')) return "React Native";
  if (fs.existsSync(path.join(root, "pubspec.yaml"))) return "Flutter";
  if (platform === "android") return "Native Android";
  if (platform === "ios") return "Native iOS";
  return "Unknown";
}

function findFile(root: string, candidates: string[]): string | null {
  for (const candidate of candidates) {
    const exact = path.join(root, candidate);
    if (fs.existsSync(exact)) return exact;
    const candidatePattern = candidate.replace(/\/\*\*\//g, "/");
    const result = findByGlob(root, candidatePattern);
    if (result) return result;
  }
  return null;
}

function findByGlob(root: string, pattern: string): string | null {
  const normalized = pattern.replace(/\\/g, "/");
  const segments = normalized.split("/");
  const searchFrom = path.join(root, segments[0] || "");
  if (!fs.existsSync(searchFrom)) return null;

  const stack = [searchFrom];
  while (stack.length) {
    const current = stack.pop();
    if (!current) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const next = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (segments.length > 1 && entry.name === segments[1]) {
          stack.push(next);
        } else {
          stack.push(next);
        }
      } else if (entry.name === path.basename(normalized) || normalized.endsWith("**") || normalized.includes("*")) {
        if (matchesGlob(path.relative(root, next), normalized)) return next;
      }
    }
  }
  return null;
}

function matchesGlob(filePath: string, pattern: string): boolean {
  const regex = new RegExp(`^${pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, ".*")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, ".")}$`);
  return regex.test(filePath.replace(/\\/g, "/"));
}

function readText(fileOrDir: string): string {
  try {
    const stats = fs.statSync(fileOrDir);
    if (stats.isDirectory()) {
      return "";
    }
    return fs.readFileSync(fileOrDir, "utf8");
  } catch {
    return "";
  }
}

function extractNumber(text: string, pattern: RegExp): number | null {
  const match = text.match(pattern);
  if (!match?.[1]) return null;
  const value = Number.parseInt(match[1], 10);
  return Number.isFinite(value) ? value : null;
}

function extractString(text: string, pattern: RegExp): string | null {
  const match = text.match(pattern);
  return match?.[1] ?? null;
}

function containsLargeResource(root: string): boolean {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const current = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (["node_modules", ".git", "Pods", "build", "DerivedData"].includes(entry.name)) continue;
        walk(current);
      } else {
        files.push(current);
      }
    }
  };

  try {
    walk(root);
  } catch {
    return false;
  }

  return files.some((file) => {
    const stat = fs.statSync(file);
    return /\.(png|jpg|jpeg|gif|mov|mp4|m4v|pdf|zip)$/i.test(file) && stat.size > 20 * 1024 * 1024;
  });
}

function calculateScore(findings: MobileFinding[]): number {
  const penaltyMap: Record<Severity, number> = { critical: 35, high: 20, medium: 10, low: 4, info: 0 };
  const totalPenalty = findings.reduce((sum, finding) => sum + (penaltyMap[finding.severity] ?? 0), 0);
  const softenedPenalty = totalPenalty * 0.55;
  return Math.max(0, Math.min(100, Math.round(100 - softenedPenalty)));
}

function gradeForScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}
