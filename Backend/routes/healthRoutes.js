
import express from "express";
import mongoose from "mongoose";

const router = express.Router();

router.get("/", (req, res) => {
  const connected = mongoose.connection.readyState === 1;

  res.status(connected ? 200 : 503).json({
    success: connected,
    application: "SecureScan AI",
    service: "Backend API",
    status: connected ? "healthy" : "degraded",
    database: connected ? "connected" : "disconnected",
    timestamp: new Date().toISOString(),
  });
});

export default router;
