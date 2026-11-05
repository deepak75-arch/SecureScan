
import { createHash } from "node:crypto";
import Upload from "../models/Upload.js";

async function requireUploadAccess(req, res, next) {
  try {
    const authorization = req.get("Authorization") || "";

    const match = authorization.match(
      /^Bearer\s+([a-f0-9]{64})$/i
    );

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Upload authorization token is missing or invalid.",
      });
    }

    const tokenHash = createHash("sha256")
      .update(match[1])
      .digest("hex");

    const upload = await Upload.findOne({
      uploadId: req.params.uploadId,
      accessTokenHash: tokenHash,
    }).select("+accessTokenHash");

    if (!upload) {
      return res.status(404).json({
        success: false,
        message: "Upload not found or access denied.",
      });
    }

    req.upload = upload;

    next();
  } catch (error) {
    next(error);
  }
}

export default requireUploadAccess;
