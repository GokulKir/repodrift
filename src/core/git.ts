import { execFileSync } from "node:child_process";
import type { GitSummary } from "./types.js";

function git(root: string, args: string[]): string | null {
	try { return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; }
}

export function analyzeGit(root: string): GitSummary {
	if (git(root, ["rev-parse", "--is-inside-work-tree"]) !== "true") return { isRepository: false, branch: null, status: "unavailable", commitCount: 0, contributors: 0, recentCommits: [], uncommittedFiles: 0 };
	const statusLines = git(root, ["status", "--porcelain"])?.split("\n").filter(Boolean) ?? [];
	const count = Number(git(root, ["rev-list", "--count", "HEAD"]) ?? 0);
	const contributors = new Set((git(root, ["shortlog", "-sne", "HEAD"]) ?? "").split("\n").filter(Boolean)).size;
	return { isRepository: true, branch: git(root, ["branch", "--show-current"]) || " detached", status: statusLines.length ? "dirty" : "clean", commitCount: Number.isFinite(count) ? count : 0, contributors, recentCommits: (git(root, ["log", "-5", "--pretty=%h %s"]) ?? "").split("\n").filter(Boolean), uncommittedFiles: statusLines.length };
}
