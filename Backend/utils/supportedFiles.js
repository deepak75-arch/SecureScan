
import path from "node:path";

export const SUPPORTED_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".py",
  ".java",
  ".c",
  ".h",
  ".cpp",
  ".hpp",
  ".cc",
  ".cs",
  ".php",
  ".go",
  ".rb",
  ".html",
  ".htm",
  ".css",
  ".scss",
  ".sass",
  ".sql",
  ".sh",
  ".bash",
  ".json",
  ".xml",
  ".yaml",
  ".yml",
  ".toml",
]);

export function isSupportedSourceFile(filename) {
  const extension = path.extname(filename).toLowerCase();
  return SUPPORTED_EXTENSIONS.has(extension);
}
