export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  category: "security" | "dependencies" | "codeQuality" | "git" | "maintenance";
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  remediation: string;
  confidence: number;
}

export interface FileSummary {
  totalFiles: number;
  totalDirectories: number;
  sourceFiles: number;
  testFiles: number;
  configurationFiles: number;
  documentationFiles: number;
  generatedFiles: number;
  binaryFiles: number;
  largeFiles: string[];
  byExtension: Record<string, number>;
  files: string[];
}

export interface DependencySummary {
  manifest: string | null;
  total: number;
  production: number;
  development: number;
  lockfiles: string[];
  findings: Finding[];
}

export interface SecuritySummary {
  findings: Finding[];
  scannedFiles: number;
}

export interface GitSummary {
  isRepository: boolean;
  branch: string | null;
  status: "clean" | "dirty" | "unavailable";
  commitCount: number;
  contributors: number;
  recentCommits: string[];
  uncommittedFiles: number;
}

export interface MetricsSummary {
  linesOfCode: number;
  averageFileSize: number;
  largestFile: string | null;
}

export interface HealthScore {
  score: number;
  grade: string;
  categories: Record<string, number>;
}

export interface RepositoryAnalysis {
  repository: { path: string; name: string };
  files: FileSummary;
  dependencies: DependencySummary;
  security: SecuritySummary;
  git: GitSummary;
  codeQuality: { findings: Finding[] };
  complexity: MetricsSummary;
  technicalDebt: { findings: Finding[] };
  score: HealthScore;
  findings: Finding[];
}