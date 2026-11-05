
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";

import Upload from "../models/Upload.js";
import Scan from "../models/Scan.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BACKEND_ROOT = path.resolve(__dirname, "..");
const UPLOAD_ROOT = path.join(BACKEND_ROOT, "uploads");

const UPLOAD_RETENTION_HOURS = 24;
const SCAN_RETENTION_DAYS = 30;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let cleanupTimer = null;
let cleanupRunning = false;

function getCutoff(hours) {
    return new Date(Date.now() - hours * 60 * 60 * 1000);
}

// --------------------------------------------------
// Delete expired uploaded files and upload metadata
// --------------------------------------------------

async function cleanupExpiredUploads() {
    const cutoff = getCutoff(UPLOAD_RETENTION_HOURS);

    const expiredUploads = await Upload.find({
        createdAt: { $lte: cutoff },
    })
        .select("uploadId createdAt")
        .lean();

    let deleted = 0;
    let skipped = 0;

    for (const upload of expiredUploads) {
        const { uploadId } = upload;

        if (!UUID_PATTERN.test(uploadId)) {
            console.error(
                `[Retention] Skipping invalid upload ID: ${uploadId}`
            );
            skipped++;
            continue;
        }

        // Never delete files used by an active scan.
        const activeScan = await Scan.exists({
            uploadId,
            status: { $in: ["queued", "scanning"] },
        });

        if (activeScan) {
            console.log(
                `[Retention] Skipping active upload: ${uploadId}`
            );
            skipped++;
            continue;
        }

        const uploadDirectory = path.resolve(
            UPLOAD_ROOT,
            uploadId
        );

        // Ensure the directory is directly inside uploads.
        if (path.dirname(uploadDirectory) !== UPLOAD_ROOT) {
            console.error(
                `[Retention] Unsafe upload path rejected: ${uploadId}`
            );
            skipped++;
            continue;
        }

        try {
            // Delete the source files and extracted contents.
            try {
                const stats = await fs.lstat(uploadDirectory);

                if (stats.isSymbolicLink() || !stats.isDirectory()) {
                    throw new Error(
                        "Upload path is not a regular directory."
                    );
                }

                await fs.rm(uploadDirectory, {
                    recursive: true,
                    force: true,
                });
            } catch (error) {
                if (error.code !== "ENOENT") {
                    throw error;
                }
            }

            // Delete metadata only after filesystem cleanup succeeds.
            await Upload.deleteOne({ uploadId });

            console.log(
                `[Retention] Deleted expired upload: ${uploadId}`
            );

            deleted++;
        } catch (error) {
            console.error(
                `[Retention] Failed to delete upload ${uploadId}:`,
                error.message
            );

            skipped++;
        }
    }

    console.log(
        `[Retention] Upload cleanup finished. Deleted: ${deleted}, skipped: ${skipped}`
    );
}

// --------------------------------------------------
// Delete old completed and failed scan records
// --------------------------------------------------

async function cleanupExpiredScans() {
    const cutoff = getCutoff(SCAN_RETENTION_DAYS);

    const result = await Scan.deleteMany({
        status: { $in: ["completed", "failed"] },
        $or: [
            { completedAt: { $lte: cutoff } },
            {
                completedAt: null,
                createdAt: { $lte: cutoff },
            },
        ],
    });

    console.log(
        `[Retention] Deleted ${result.deletedCount} expired scan records.`
    );
}

// --------------------------------------------------
// Run all retention jobs
// --------------------------------------------------

export async function runRetentionCleanup() {
    if (cleanupRunning) {
        console.log(
            "[Retention] Previous cleanup is still running. Skipping."
        );
        return;
    }

    cleanupRunning = true;

    console.log("[Retention] Starting cleanup...");

    try {
        await cleanupExpiredUploads();
        await cleanupExpiredScans();

        console.log("[Retention] Cleanup completed.");
    } catch (error) {
        console.error(
            "[Retention] Cleanup failed:",
            error.message
        );
    } finally {
        cleanupRunning = false;
    }
}

// --------------------------------------------------
// Start hourly cleanup scheduler
// --------------------------------------------------

export function startRetentionCleanup() {
    if (cleanupTimer) {
        console.log(
            "[Retention] Scheduler is already running."
        );
        return;
    }

    // Run once when the backend starts.
    void runRetentionCleanup();

    // Run every hour.
    cleanupTimer = setInterval(() => {
        void runRetentionCleanup();
    }, CLEANUP_INTERVAL_MS);

    console.log(
        "[Retention] Scheduler started. Cleanup interval: 1 hour."
    );
}

export function stopRetentionCleanup() {
    if (cleanupTimer) {
        clearInterval(cleanupTimer);
        cleanupTimer = null;
        console.log("[Retention] Scheduler stopped.");
    }
}
