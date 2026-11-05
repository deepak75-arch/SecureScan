
import express from "express";
import { startScan } from "../scanners/scanRunner.js";
import requireScanAccess from "../middleware/requireScanAccess.js";
import requireUploadAccess from "../middleware/requireUploadAccess.js";

const router = express.Router();

// Start a new scan.
// Requires the private upload access token.
router.post(
  "/:uploadId",
  requireUploadAccess,
  async (req, res, next) => {
    try {
      const result = await startScan(req.params.uploadId);

      return res.status(202).json(result);
    } catch (error) {
      next(error);
    }
  }
);

// Public scan listing is disabled.
// Each scan must be accessed using its private token.
router.get("/", (req, res) => {
  return res.status(403).json({
    success: false,
    message: "Public scan history is disabled.",
  });
});

// Get one scan using its private access token.
router.get(
  "/:scanId",
  requireScanAccess,
  async (req, res, next) => {
    try {
      return res.status(200).json({
        success: true,
        scan: req.scan,
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
