#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import { analyzeRepository } from './core/engine.js';
import { scanMobileHealth } from './core/mobile.js';
import type { Finding, Severity } from './core/types.js';

const program = new Command();

program
  .name("repodrift")
  .description("AI-powered repository analysis CLI")
  .version("0.1.6");

// Banner display
function printBanner(): void {
  const banner = `
    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ██████╗ ██╗███████╗████████╗
    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝
    ██████╔╝█████╗  ██████╔╝██║   ██║██║  ██║██████╔╝██║█████╗     ██║   
    ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██║  ██║██╔══██╗██║██╔══╝     ██║   
    ██║  ██║███████╗██║     ╚██████╔╝██████╔╝██║  ██║██║██║        ██║   
    ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   
  `;
  console.log(chalk.cyan(banner));
  console.log(chalk.gray.italic("    Repository Intelligence & Security Analysis\n"));
}

// Animated loading dots
function createAnimatedSpinner(message: string): Ora & { stop: () => void; succeed: (msg?: string) => void; fail: (msg?: string) => void } {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let frameIndex = 0;
  let isRunning = true;

  const spinner = ora({
    text: message,
    spinner: {
      interval: 80,
      frames
    }
  }).start();

  return {
    ...spinner,
    stop: () => {
      isRunning = false;
      spinner.stop();
    },
    succeed: (msg?: string) => {
      isRunning = false;
      spinner.succeed(msg);
    },
    fail: (msg?: string) => {
      isRunning = false;
      spinner.fail(msg);
    }
  } as Ora & { stop: () => void; succeed: (msg?: string) => void; fail: (msg?: string) => void };
}

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
    if (!options.json) {
      printBanner();
    }
    
    const spinner = options.json ? null : createAnimatedSpinner("Scanning repository...");
    try {
      const analysis = analyzeRepository(inputPath, { audit: options.localOnly !== true });
      spinner?.succeed("Scan completed successfully");
      
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

const mobileCommand = new Command("mobile");
mobileCommand
  .description("Scan a mobile app project")
  .addHelpCommand(false);

mobileCommand
  .command("scan")
  .description("Scan a mobile app project")
  .argument("[path]", "Mobile project path", ".")
  .option("--json", "Output machine-readable JSON")
  .action((inputPath: string, options: { json?: boolean }) => {
    const spinner = options.json ? null : ora("Detecting mobile project and scanning health...").start();
    try {
      const analysis = scanMobileHealth(inputPath);
      spinner?.stop();
      if (options.json) {
        console.log(JSON.stringify(analysis, null, 2));
      } else {
        printMobileReport(analysis);
      }
    } catch (error) {
      spinner?.fail("Mobile scan failed");
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

program.addCommand(mobileCommand);
program.parse();

function printReport(analysis: ReturnType<typeof analyzeRepository>, verbose: boolean): void {
  console.log(`${chalk.bold.cyan("━".repeat(80))}`);
  console.log(`${chalk.bold.cyan("Repository:")} ${analysis.repository.name}`);
  console.log(`${chalk.bold.cyan("Files:")} ${analysis.files.totalFiles}  ${chalk.bold.cyan("Directories:")} ${analysis.files.totalDirectories}`);
  console.log(`${chalk.bold.cyan("Dependencies:")} ${analysis.dependencies.total}  ${chalk.bold.cyan("Security Issues:")} ${analysis.security.findings.length}`);
  console.log(`${chalk.bold.cyan("━".repeat(80))}\n`);

  // Health Score section
  const scoreColor = analysis.score.score >= 80 ? chalk.green : analysis.score.score >= 60 ? chalk.yellow : chalk.red;
  console.log(chalk.bold(`📊 Health Score`));
  console.log(`   Overall: ${scoreColor(chalk.bold(`${analysis.score.score} / 100`))}  Grade: ${scoreColor(chalk.bold(analysis.score.grade))}`);
  console.log(`   Security: ${analysis.score.categories.security}/100  Dependencies: ${analysis.score.categories.dependencies}/100  Code Quality: ${analysis.score.categories.codeQuality}/100`);
  console.log();

  if (verbose) {
    console.log(chalk.bold(`📈 Metrics`));
    console.log(`   Lines of Code: ${analysis.complexity.linesOfCode}`);
    console.log(`   Average File Size: ${analysis.complexity.averageFileSize} bytes`);
    if (analysis.git.isRepository) {
      console.log(`   Git Branch: ${analysis.git.branch}`);
      console.log(`   Commits: ${analysis.git.commitCount}  Contributors: ${analysis.git.contributors}`);
      console.log(`   Status: ${analysis.git.status}`);
    }
    console.log();
  }

  // Findings section with detailed information
  printDetailedFindings(analysis.findings);
  console.log(chalk.gray("\n💡 Run `repodrift scan --json` for CI/CD integration."));
  console.log(chalk.gray(`   Run \`repodrift scan --verbose\` for detailed metrics.\n`));
}

function printDetailedFindings(findings: Finding[]): void {
  if (!findings.length) {
    console.log(`${chalk.green("✓ No actionable findings detected. Repository looks healthy!")}`);
    return;
  }

  // Group findings by severity
  const bySeverity: Record<string, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: []
  };

  for (const finding of findings) {
    if (bySeverity[finding.severity]) {
      bySeverity[finding.severity].push(finding);
    }
  }

  console.log(chalk.bold(`🔍 Findings (${findings.length} total)`));
  console.log();

  // Display by severity
  for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    const items = bySeverity[severity];
    if (items.length === 0) continue;

    const severityColor = severity === 'critical' ? chalk.red : severity === 'high' ? chalk.red : severity === 'medium' ? chalk.yellow : severity === 'low' ? chalk.blue : chalk.gray;
    const severityIcon = severity === 'critical' ? '🔴' : severity === 'high' ? '🔴' : severity === 'medium' ? '🟡' : severity === 'low' ? '🔵' : '⚪';
    
    console.log(severityColor(`${severityIcon} ${severity.toUpperCase()} SEVERITY (${items.length})`));
    console.log(severityColor(chalk.dim("─".repeat(80))));

    for (let i = 0; i < Math.min(items.length, 20); i++) {
      const finding = items[i];
      console.log();
      console.log(`  ${severityColor(chalk.bold(`${i + 1}. ${finding.title}`))}`);
      console.log(`     ${chalk.gray(`Category:`)} ${finding.category}`);
      
      if (finding.file) {
        console.log(`     ${chalk.gray(`File:`)} ${finding.file}${finding.line ? chalk.cyan(`:${finding.line}`) : ''}`);
      }

      console.log(`     ${chalk.gray(`Description:`)} ${finding.description}`);
      console.log();
      console.log(`     ${chalk.bold(`Why it matters:`)}`);
      const remediation = finding.remediation;
      const whyAndFix = remediation.split('\n\n');
      if (whyAndFix.length > 1) {
        console.log(`     ${whyAndFix[0]}`);
        console.log();
        console.log(`     ${chalk.bold(`How to fix:`)}`);
        const fixLines = whyAndFix.slice(1).join('\n\n').split('\n');
        for (const line of fixLines) {
          console.log(`     ${line}`);
        }
      } else {
        console.log(`     ${finding.remediation}`);
      }
      console.log();
    }

    if (items.length > 20) {
      console.log(chalk.gray(`  ... and ${items.length - 20} more ${severity} severity issues`));
    }
    console.log();
  }
}

function printMobileReport(analysis: ReturnType<typeof scanMobileHealth>): void {
  console.log(`\n${chalk.bold.cyan("RepoDrift")} ${chalk.gray("Mobile Health")}`);
  console.log(`\nPlatform       ${analysis.platform === "unknown" ? "Unknown" : analysis.platform.charAt(0).toUpperCase() + analysis.platform.slice(1)}`);
  console.log(`Framework      ${analysis.framework}`);
  console.log(`Health Score   ${chalk.bold(`${analysis.score} / 100`)}`);
  console.log(`Grade          ${chalk.bold(analysis.grade)}`);
  console.log("");

  for (const check of analysis.checks) {
    const status = check.status === "pass" ? chalk.green("✓") : check.status === "warn" ? chalk.yellow("⚠") : chalk.red("✕");
    console.log(`${status} ${check.name}: ${check.detail}`);
  }

  if (analysis.findings.length) {
    console.log("\nIssues:");
    for (const finding of analysis.findings.slice(0, 10)) {
      const severity = finding.severity === "high" || finding.severity === "critical" ? chalk.red : finding.severity === "medium" ? chalk.yellow : chalk.gray;
      console.log(`${severity(finding.severity.toUpperCase())} ${finding.title}`);
    }
  }
}

function severityRank(severity: Severity): number {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity] ?? 5;
}