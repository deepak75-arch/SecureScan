
function requireUploadConsent(req, res, next) {
    const consent = req.get("X-Upload-Consent");

    if (consent !== "true") {
        return res.status(400).json({
            success: false,
            message:
                "Upload authorization is required. Please confirm that you have permission to scan these files."
        });
    }

    next();
}

export default requireUploadConsent;
