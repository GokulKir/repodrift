#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { analyzeRepository } from './core/engine.js';
import type { Finding, Severity } from './core/types.js';

const program = new Command();

program
  .name("repodrift")
  .description("AI-powered repository analysis CLI")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a repository")
  .argument("[path]", "Repository path", ".")
  .option("--json", "Output machine-readable JSON")
  .option("--verbose", "Show detailed analysis metrics")
  .option("--no-ai", "Disable AI analysis")
  .option("--local-only", "Guarantee that no network request is made")
  .option("--fail-on <severity>", "Exit non-zero for findings at or above severity", "critical")
  .action((inputPath: string, options: { json?: boolean; verbose?: boolean; localOnly?: boolean; failOn: string }) => {
    const spinner = options.json ? null : ora("Scanning repository...").start();
    try {
      const analysis = analyzeRepository(inputPath, { audit: options.localOnly !== true });
      spinner?.stop();
      if (options.json) {
        console.log(JSON.stringify(analysis, null, 2));
      } else {
        printReport(analysis, options.verbose === true);
      }
      const threshold = severityRank(options.failOn as Severity);
      if (analysis.findings.some((finding) => severityRank(finding.severity) >= threshold)) process.exitCode = threshold >= severityRank("critical") ? 2 : 1;
    } catch (error) {
      spinner?.fail("Scan failed");
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

program.parse();

function printReport(analysis: ReturnType<typeof analyzeRepository>, verbose: boolean): void {
  console.log(`\n${chalk.bold.cyan("RepoDrift")} ${chalk.gray("Repository Intelligence")}`);
  console.log(`\nRepository: ${analysis.repository.name}`);
  console.log(`Files: ${analysis.files.totalFiles}  Directories: ${analysis.files.totalDirectories}`);
  console.log(`Dependencies: ${analysis.dependencies.total}  Security issues: ${analysis.security.findings.length}`);
  console.log(`\n${chalk.bold("Health Score")}  ${chalk.bold(`${analysis.score.score} / 100`)}  Grade: ${chalk.bold(analysis.score.grade)}`);
  console.log(`Security ${analysis.score.categories.security}  Dependencies ${analysis.score.categories.dependencies}  Code quality ${analysis.score.categories.codeQuality}`);
  if (verbose) console.log(`\nLines of code: ${analysis.complexity.linesOfCode}\nGit: ${analysis.git.isRepository ? `${analysis.git.branch}, ${analysis.git.commitCount} commits` : "unavailable"}`);
  printFindings(analysis.findings);
  console.log(chalk.gray("\nRun `repodrift scan --json` for CI integration."));
}

function printFindings(findings: Finding[]): void {
  if (!findings.length) { console.log(`\n${chalk.green("No actionable findings detected.")}`); return; }
  console.log(`\n${chalk.bold("Findings")}`);
  for (const finding of findings.slice(0, 20)) {
    const color = finding.severity === "critical" || finding.severity === "high" ? chalk.red : finding.severity === "medium" ? chalk.yellow : chalk.gray;
    console.log(`${color(finding.severity.toUpperCase())} ${finding.title}${finding.file ? ` - ${finding.file}${finding.line ? `:${finding.line}` : ""}` : ""}`);
  }
  if (findings.length > 20) console.log(chalk.gray(`...and ${findings.length - 20} more`));
}

function severityRank(severity: Severity): number {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity] ?? 5;
}