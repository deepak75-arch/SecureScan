const STORAGE_KEY = "securescan:upload-access:v1";

function readAccessMap() {
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    if (!stored) return {};

    const parsed = JSON.parse(stored);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }

    return parsed;
  } catch (error) {
    console.error("Unable to read upload access storage:", error);
    return {};
  }
}

function writeAccessMap(accessMap) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(accessMap));
    return true;
  } catch (error) {
    console.error("Unable to save upload access token:", error);
    return false;
  }
}

export function saveUploadAccess(uploadId, accessToken) {
  if (
    typeof uploadId !== "string" || !uploadId.trim() ||
    typeof accessToken !== "string" || !accessToken.trim()
  ) {
    throw new Error("The upload ID or access token is missing.");
  }

  const accessMap = readAccessMap();
  accessMap[uploadId] = accessToken;

  if (!writeAccessMap(accessMap)) {
    throw new Error(
      "Could not save upload access. Please enable browser session storage."
    );
  }

  if (getUploadAccessToken(uploadId) !== accessToken) {
    throw new Error("Upload access token verification failed.");
  }

  return true;
}

export function getUploadAccessToken(uploadId) {
  if (typeof uploadId !== "string" || !uploadId.trim()) return null;

  const token = readAccessMap()[uploadId];
  return typeof token === "string" && token.trim() ? token : null;
}

export function removeUploadAccess(uploadId) {
  if (typeof uploadId !== "string" || !uploadId.trim()) return;

  const accessMap = readAccessMap();
  delete accessMap[uploadId];
  writeAccessMap(accessMap);
}
