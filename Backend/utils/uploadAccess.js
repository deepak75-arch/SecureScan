
const STORAGE_KEY = "securescan:upload-access:v1";

function readAccessMap() {
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    const parsed = stored ? JSON.parse(stored) : {};

    return parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed)
      ? parsed
      : {};
  } catch {
    return {};
  }
}

export function saveUploadAccess(uploadId, accessToken) {
  if (!uploadId || !accessToken) {
    throw new Error("Upload ID or access token is missing.");
  }

  const accessMap = readAccessMap();
  accessMap[uploadId] = accessToken;

  sessionStorage.setItem(
    STORAGE_KEY,
    JSON.stringify(accessMap)
  );
}

export function getUploadAccessToken(uploadId) {
  if (!uploadId) return null;

  return readAccessMap()[uploadId] || null;
}
