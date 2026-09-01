import fs from "node:fs";
import path from "node:path";
import type { FileSummary } from "./types.js";

const IGNORED_DIRECTORIES = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", ".cache"]);
const LARGE_FILE_BYTES = 1024 * 1024;

export function scanRepository(root: string): FileSummary {
  const files: string[] = [];
  const byExtension: Record<string, number> = {};
  let totalDirectories = 0;
  let sourceFiles = 0;
  let testFiles = 0;
  let configurationFiles = 0;
  let documentationFiles = 0;
  let generatedFiles = 0;
  let binaryFiles = 0;
  const largeFiles: string[] = [];
  const ignorePatterns = readIgnoreFile(root);

  function walk(dir: string) {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const item = entry.name;
      const relative = path.relative(root, path.join(dir, item));
      if ((entry.isDirectory() && IGNORED_DIRECTORIES.has(item)) || matchesIgnore(relative, ignorePatterns)) {
        continue;
      }

      const fullPath = path.join(dir, item);
      if (entry.isDirectory()) {
        totalDirectories++;
        walk(fullPath);
      } else {
        files.push(relative);
        const extension = path.extname(item).toLowerCase() || "[no extension]";
        byExtension[extension] = (byExtension[extension] ?? 0) + 1;
        if (/\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|cpp|h)$/i.test(item)) sourceFiles++;
        if (/(?:^|[._-])(test|spec)(?:[._-]|$)/i.test(item) || /(?:^|\/)test[s]?(?:\/|$)/i.test(relative)) testFiles++;
        if (/^(?:\.|tsconfig|package-lock|yarn\.lock|pnpm-lock|webpack|vite|eslint|prettier)/i.test(item) || /\.(?:json|ya?ml|toml|ini|conf)$/i.test(item)) configurationFiles++;
        if (/\.(?:md|mdx|txt|rst)$/i.test(item)) documentationFiles++;
        if (/(?:dist|build|generated|\.min\.)/i.test(relative)) generatedFiles++;
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > LARGE_FILE_BYTES) largeFiles.push(relative);
          if (isBinary(fullPath, stat.size)) binaryFiles++;
        } catch { /* Files can disappear during a scan. */ }
      }
    }
  }

  walk(path.resolve(root));

  return {
    totalFiles: files.length,
    totalDirectories, sourceFiles, testFiles, configurationFiles, documentationFiles,
    generatedFiles, binaryFiles, largeFiles, byExtension, files: files.sort()
  };
}

function readIgnoreFile(root: string): string[] {
  try { return fs.readFileSync(path.join(root, ".repodriftignore"), "utf8").split(/\r?\n/).filter(Boolean); }
  catch { return []; }
}

function matchesIgnore(file: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    const clean = pattern.replace(/^\//, "").replace(/\/$/, "");
    if (clean.includes("*")) return new RegExp(`^${clean.split("*").map(escapeRegex).join(".*")}(?:/.*)?$`).test(file);
    return file === clean || file.startsWith(`${clean}/`);
  });
}

function escapeRegex(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function isBinary(file: string, size: number): boolean {
  if (size === 0) return false;
  if (/\.(?:png|jpe?g|gif|webp|ico|pdf|zip|gz|woff2?|ttf|exe|dylib)$/i.test(file)) return true;
  try { return fs.readFileSync(file).subarray(0, 512).includes(0); } catch { return false; }
}