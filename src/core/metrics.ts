import fs from "node:fs";
import path from "node:path";
import type { Finding, MetricsSummary } from "./types.js";

export function calculateMetrics(root: string, files: string[]): MetricsSummary {
	let linesOfCode = 0;
	let largestFile: string | null = null;
	let largestSize = 0;
	for (const relative of files) {
		if (!/\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|cpp|h)$/i.test(relative)) continue;
		try { const size = fs.statSync(path.join(root, relative)).size; const content = fs.readFileSync(path.join(root, relative), "utf8"); linesOfCode += content.split("\n").length; if (size > largestSize) { largestSize = size; largestFile = relative; } } catch { /* Ignore files that cannot be read. */ }
	}
	return { linesOfCode, averageFileSize: files.length ? Math.round(largestSize / files.length) : 0, largestFile };
}

export function qualityFindings(metrics: MetricsSummary): Finding[] {
	return metrics.largestFile && metrics.linesOfCode > 0 && metrics.linesOfCode > 1000 ? [{ id: "quality.large-codebase-file", category: "codeQuality", severity: "low", title: "Repository contains a large source footprint", description: "Large source footprints are harder to review and maintain.", file: metrics.largestFile, remediation: "Consider splitting the largest modules by responsibility.", confidence: 0.7 }] : [];
}
