import { createHash } from "node:crypto";
import Scan from "../models/Scan.js";

async function requireScanAccess(req, res, next) {
  try {
    const authorization = req.get("Authorization") || "";
    const match = authorization.match(/^Bearer ([a-f0-9]{64})$/i);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "A valid scan access token is required.",
      });
    }

    const tokenHash = createHash("sha256")
      .update(match[1])
      .digest("hex");

    const scan = await Scan.findOne({
      scanId: req.params.scanId,
      accessTokenHash: tokenHash,
    }).lean();

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found or access denied.",
      });
    }

    req.scan = scan;
    next();
  } catch (error) {
    next(error);
  }
}

export default requireScanAccess;