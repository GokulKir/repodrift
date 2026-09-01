import path from "node:path";
import { analyzeDependencies } from "./dependencies.js";
import { analyzeGit } from "./git.js";
import { calculateMetrics, qualityFindings } from "./metrics.js";
import { scanRepository } from "./scanner.js";
import { scanSecurity } from "./security.js";
import type { Finding, HealthScore, RepositoryAnalysis } from "./types.js";

export function calculateHealthScore(findings: Finding[], gitAvailable: boolean): HealthScore {
  const penalty = (category: string) => findings.filter((finding) => finding.category === category).reduce((sum, finding) => sum + ({ critical: 35, high: 20, medium: 10, low: 4, info: 0 }[finding.severity] ?? 0), 0);
  const categories = { security: Math.max(0, 100 - penalty("security")), dependencies: Math.max(0, 100 - penalty("dependencies")), codeQuality: Math.max(0, 100 - penalty("codeQuality")), complexity: 85, git: gitAvailable ? 90 : 60, maintenance: 85 };
  const score = Math.round(categories.security * .3 + categories.dependencies * .2 + categories.codeQuality * .2 + categories.complexity * .15 + categories.git * .1 + categories.maintenance * .05);
  return { score, grade: score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F", categories };
}

export function analyzeRepository(inputPath: string, options: { audit?: boolean } = {}): RepositoryAnalysis {
  const root = path.resolve(inputPath);
  const files = scanRepository(root);
  const dependencies = analyzeDependencies(root, options);
  const security = scanSecurity(root, files.files);
  const git = analyzeGit(root);
  const complexity = calculateMetrics(root, files.files);
  const codeQuality = qualityFindings(complexity);
  const findings = [...security.findings, ...dependencies.findings, ...codeQuality];
  return { repository: { path: root, name: path.basename(root) }, files, dependencies, security, git, codeQuality: { findings: codeQuality }, complexity, technicalDebt: { findings: codeQuality }, score: calculateHealthScore(findings, git.isRepository), findings };
}