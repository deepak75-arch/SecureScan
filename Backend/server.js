
import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";

import reportRoutes from "./routes/reportRoutes.js";
import scanRoutes from "./routes/scanRoutes.js";
import connectDB from "./config/db.js";
import healthRoutes from "./routes/healthRoutes.js";
import uploadRoutes from "./routes/uploadRoutes.js";

import {
    startRetentionCleanup,
    stopRetentionCleanup,
} from "./services/retentionCleanup.js";

const app = express();

const PORT = process.env.PORT || 5000;
const FRONTEND_URL =
    process.env.FRONTEND_URL || "http://localhost:5173";

// Security middleware
app.use(helmet());

app.use(
    cors({
        origin: FRONTEND_URL,
        methods: ["GET", "POST", "DELETE"],
    })
);

app.use(express.json({ limit: "1mb" }));

// Root endpoint
app.get("/", (req, res) => {
    res.json({
        message: "Welcome to SecureScan Backend",
        status: "running",
    });
});

// API routes
app.use("/api/reports", reportRoutes);
app.use("/api/health", healthRoutes);
app.use("/api/uploads", uploadRoutes);
app.use("/api/scans", scanRoutes);

// Central error handler
app.use((error, req, res, next) => {
    console.error("API Error:", error.message);

    if (error instanceof multer.MulterError) {
        const status =
            error.code === "LIMIT_FILE_SIZE" ||
            error.code === "LIMIT_FILE_COUNT"
                ? 413
                : 400;

        return res.status(status).json({
            success: false,
            message: error.message,
        });
    }

    if (
        error.message?.startsWith(
            "Unsupported file type:"
        )
    ) {
        return res.status(400).json({
            success: false,
            message: error.message,
        });
    }

    return res.status(500).json({
        success: false,
        message: "Internal server error.",
    });
});

// Unknown routes
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "API endpoint not found",
    });
});

// Start server
const startServer = async () => {
    try {
        await connectDB();

        startRetentionCleanup();

        const server = app.listen(PORT, "0.0.0.0", () => {
            console.log(`SecureScan AI backend running on port ${PORT}`);
         });

        // Graceful shutdown
        const shutdown = (signal) => {
            console.log(`${signal} received. Shutting down...`);

            stopRetentionCleanup();

            server.close(() => {
                console.log("HTTP server closed.");
                process.exit(0);
            });

            setTimeout(() => {
                console.error("Forced shutdown.");
                process.exit(1);
            }, 10000).unref();
        };

        process.once("SIGINT", () => shutdown("SIGINT"));
        process.once("SIGTERM", () => shutdown("SIGTERM"));

    } catch (error) {
        console.error(
            "Server startup failed:",
            error.message
        );

        process.exit(1);
    }
};

startServer();
