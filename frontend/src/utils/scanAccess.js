const STORAGE_KEY = "securescan:scan-access:v1";

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
    console.error("Unable to read scan access storage:", error);
    return {};
  }
}

function writeAccessMap(accessMap) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(accessMap));
    return true;
  } catch (error) {
    console.error("Unable to save scan access token:", error);
    return false;
  }
}

export function saveScanAccess(scanId, accessToken) {
  if (
    typeof scanId !== "string" || !scanId.trim() ||
    typeof accessToken !== "string" || !accessToken.trim()
  ) {
    throw new Error("The scan ID or access token is missing.");
  }

  const accessMap = readAccessMap();
  accessMap[scanId] = accessToken;

  if (!writeAccessMap(accessMap)) {
    throw new Error(
      "Could not save scan access. Please enable browser session storage."
    );
  }

  if (getScanAccessToken(scanId) !== accessToken) {
    throw new Error("Scan access token verification failed.");
  }

  return true;
}

export function getScanAccessToken(scanId) {
  if (typeof scanId !== "string" || !scanId.trim()) return null;

  const token = readAccessMap()[scanId];
  return typeof token === "string" && token.trim() ? token : null;
}

export function removeScanAccess(scanId) {
  if (typeof scanId !== "string" || !scanId.trim()) return;

  const accessMap = readAccessMap();
  delete accessMap[scanId];
  writeAccessMap(accessMap);
}

export async function fetchAuthorizedScans(apiBaseUrl) {
  const accessMap = readAccessMap();
  const entries = Object.entries(accessMap);

  const results = await Promise.all(
    entries.map(async ([scanId, accessToken]) => {
      try {
        const response = await fetch(
          `${apiBaseUrl}/api/scans/${encodeURIComponent(scanId)}`,
          {
            method: "GET",
            headers: { Authorization: `Bearer ${accessToken}` },
            cache: "no-store",
          }
        );

        if (response.status === 401) {
          removeScanAccess(scanId);
          return null;
        }

        if (!response.ok) {
          console.warn(
            `Could not retrieve scan ${scanId}: HTTP ${response.status}`
          );
          return null;
        }

        const data = await response.json();
        if (!data.success || !data.scan) return null;

        const scan = data.scan;
        const findings = Array.isArray(scan.findings) ? scan.findings : [];
        const severityCounts = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        };

        findings.forEach((finding) => {
          const severity = String(finding.severity || "info").toLowerCase();
          if (Object.prototype.hasOwnProperty.call(severityCounts, severity)) {
            severityCounts[severity] += 1;
          } else {
            severityCounts.info += 1;
          }
        });

        return {
          ...scan,
          totalFindings: findings.length,
          severityCounts,
        };
      } catch (error) {
        console.error(`Error retrieving scan ${scanId}:`, error.message);
        return null;
      }
    })
  );

  return results
    .filter(Boolean)
    .sort(
      (a, b) =>
        new Date(b.createdAt || b.startedAt || 0) -
        new Date(a.createdAt || a.startedAt || 0)
    );
}
