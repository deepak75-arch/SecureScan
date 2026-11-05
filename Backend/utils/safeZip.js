
import yauzl from "yauzl";
import fs from "fs";
import path from "path";
import { pipeline } from "stream/promises";

const MAX_ENTRIES = 2000;
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB per extracted file
const MAX_TOTAL_SIZE = 200 * 1024 * 1024; // 200 MB total
const MAX_COMPRESSION_RATIO = 100;

function openZip(zipPath) {
  return new Promise((resolve, reject) => {
    yauzl.open(
      zipPath,
      {
        lazyEntries: true,
        decodeStrings: true,
        validateEntrySizes: true,
        strictFileNames: true,
      },
      (error, zipfile) => {
        if (error) return reject(error);
        resolve(zipfile);
      }
    );
  });
}

function validateEntryPath(fileName) {
  if (
    typeof fileName !== "string" ||
    !fileName ||
    fileName.includes("\0") ||
    fileName.includes("\\") ||
    fileName.startsWith("/") ||
    /^[a-zA-Z]:/.test(fileName)
  ) {
    throw new Error("Unsafe ZIP entry path detected.");
  }

  const isDirectory = fileName.endsWith("/");
  const cleanName = isDirectory
    ? fileName.slice(0, -1)
    : fileName;

  if (!cleanName) {
    throw new Error("Invalid ZIP entry path.");
  }

  const parts = cleanName.split("/");

  for (const part of parts) {
    if (
      !part ||
      part === "." ||
      part === ".." ||
      part.includes(":") ||
      /[. ]$/.test(part) ||
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i.test(part)
    ) {
      throw new Error("Unsafe ZIP entry path detected.");
    }
  }

  return {
    relativePath: parts.join(path.sep),
    isDirectory,
  };
}

function validateEntryType(entry, isDirectory) {
  const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
  const fileType = unixMode & 0o170000;

  // Reject symbolic links and special filesystem objects.
  if (
    fileType !== 0 &&
    fileType !== 0o100000 &&
    fileType !== 0o040000
  ) {
    throw new Error("ZIP contains an unsupported file type.");
  }

  if (isDirectory && fileType === 0o100000) {
    throw new Error("Invalid directory entry.");
  }

  if (!isDirectory && fileType === 0o040000) {
    throw new Error("Invalid file entry.");
  }
}

function ensureNoPathConflict(relativePath, isDirectory, seenPaths) {
  const normalized = relativePath.toLowerCase();
  const parts = normalized.split(path.sep);

  // Reject duplicate paths and file/directory conflicts.
  if (seenPaths.has(normalized)) {
    throw new Error("Duplicate ZIP entry detected.");
  }

  let current = "";

  for (let i = 0; i < parts.length; i++) {
    current = current
      ? `${current}${path.sep}${parts[i]}`
      : parts[i];

    const existing = seenPaths.get(current);
    const isLast = i === parts.length - 1;

    if (existing === "file") {
      throw new Error("ZIP entry conflicts with an existing file.");
    }

    if (isLast && existing === "directory" && !isDirectory) {
      throw new Error("ZIP file conflicts with an existing directory.");
    }

    if (!isLast && existing === "file") {
      throw new Error("ZIP entry has an invalid parent path.");
    }
  }

  // Register implicit parent directories.
  current = "";

  for (let i = 0; i < parts.length - 1; i++) {
    current = current
      ? `${current}${path.sep}${parts[i]}`
      : parts[i];

    if (!seenPaths.has(current)) {
      seenPaths.set(current, "directory");
    }
  }

  seenPaths.set(normalized, isDirectory ? "directory" : "file");
}

export async function extractZipSafely(zipPath, destination) {
  const resolvedDestination = path.resolve(destination);

  await fs.promises.mkdir(resolvedDestination, {
    recursive: false,
    mode: 0o700,
  });

  let zipfile;

  try {
    zipfile = await openZip(zipPath);

    return await new Promise((resolve, reject) => {
      let entryCount = 0;
      let totalSize = 0;
      let totalFiles = 0;
      let settled = false;

      const seenPaths = new Map();
      const extractedFiles = [];

      const cleanupAndReject = async (error) => {
        if (settled) return;
        settled = true;

        try {
          zipfile.close();
        } catch {
          // Ignore close errors during cleanup.
        }

        try {
          await fs.promises.rm(resolvedDestination, {
            recursive: true,
            force: true,
          });
        } catch {
          // Preserve the original extraction error.
        }

        reject(error);
      };

      const finish = () => {
        if (settled) return;
        settled = true;

        resolve({
          totalFiles,
          totalSize,
          files: extractedFiles,
        });
      };

      zipfile.on("error", cleanupAndReject);

      zipfile.on("entry", async (entry) => {
        if (settled) return;

        try {
          entryCount++;

          if (entryCount > MAX_ENTRIES) {
            throw new Error("ZIP contains too many entries.");
          }

          // Reject encrypted entries.
          if (entry.generalPurposeBitFlag & 0x1) {
            throw new Error("Encrypted ZIP files are not supported.");
          }

          const { relativePath, isDirectory } =
            validateEntryPath(entry.fileName);

          validateEntryType(entry, isDirectory);

          ensureNoPathConflict(
            relativePath,
            isDirectory,
            seenPaths
          );

          const outputPath = path.resolve(
            resolvedDestination,
            relativePath
          );

          const relativeCheck = path.relative(
            resolvedDestination,
            outputPath
          );

          if (
            relativeCheck.startsWith("..") ||
            path.isAbsolute(relativeCheck)
          ) {
            throw new Error("ZIP path traversal detected.");
          }

          if (isDirectory) {
            if (entry.uncompressedSize !== 0) {
              throw new Error("Invalid directory entry size.");
            }

            await fs.promises.mkdir(outputPath, {
              recursive: true,
              mode: 0o700,
            });

            zipfile.readEntry();
            return;
          }

          if (
            entry.uncompressedSize > MAX_FILE_SIZE ||
            entry.uncompressedSize < 0
          ) {
            throw new Error("Extracted file exceeds the size limit.");
          }

          if (
            entry.uncompressedSize > 0 &&
            entry.compressedSize === 0
          ) {
            throw new Error("Invalid ZIP compression metadata.");
          }

          if (
            entry.compressedSize > 0 &&
            entry.uncompressedSize / entry.compressedSize >
              MAX_COMPRESSION_RATIO
          ) {
            throw new Error("ZIP compression ratio exceeds the limit.");
          }

          totalSize += entry.uncompressedSize;

          if (totalSize > MAX_TOTAL_SIZE) {
            throw new Error("Total extracted size exceeds the limit.");
          }

          await fs.promises.mkdir(path.dirname(outputPath), {
            recursive: true,
            mode: 0o700,
          });

          const readStream = await new Promise((resolve, reject) => {
            zipfile.openReadStream(entry, (error, stream) => {
              if (error) return reject(error);
              resolve(stream);
            });
          });

          let actualSize = 0;

          readStream.on("data", (chunk) => {
            actualSize += chunk.length;

            if (actualSize > MAX_FILE_SIZE) {
              readStream.destroy(
                new Error("Extracted file exceeds the size limit.")
              );
            }
          });

          const writeStream = fs.createWriteStream(outputPath, {
            flags: "wx",
            mode: 0o600,
          });

          await pipeline(readStream, writeStream);

          if (actualSize !== entry.uncompressedSize) {
            throw new Error("Extracted file size does not match ZIP metadata.");
          }

          totalFiles++;

          extractedFiles.push({
            relativePath,
            size: actualSize,
          });

          zipfile.readEntry();
        } catch (error) {
          await cleanupAndReject(error);
        }
      });

      zipfile.on("end", finish);

      zipfile.readEntry();
    });
  } catch (error) {
    try {
      if (zipfile) zipfile.close();
    } catch {
      // Ignore close errors.
    }

    await fs.promises.rm(resolvedDestination, {
      recursive: true,
      force: true,
    });

    throw error;
  }
}
