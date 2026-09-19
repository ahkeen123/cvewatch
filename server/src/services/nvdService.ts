/**
 * Service for talking to the NVD (National Vulnerability Database) CVE API.
 *
 * This MUST run server-side: NVD does not send permissive CORS headers, so
 * a browser calling it directly will be blocked. That's the whole reason
 * this app has a backend.
 *
 * Docs: https://nvd.nist.gov/developers/vulnerabilities
 *
 * Rate limits:
 *  - No API key: 5 requests / rolling 30s window
 *  - With NVD_API_KEY: 50 requests / rolling 30s window
 * We self-throttle to stay under whichever applies.
 */

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export interface NvdCveResult {
  id: string;
  description: string;
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  publishedAt: string | null;
  lastModified: string | null;
  sourceUrl: string;
  raw: unknown;
}

// --- simple in-process rate limiter --------------------------------------

const WINDOW_MS = 30_000;
const MAX_REQUESTS_NO_KEY = 5;
const MAX_REQUESTS_WITH_KEY = 50;
let requestTimestamps: number[] = [];

async function throttle(): Promise<void> {
  const limit = process.env.NVD_API_KEY ? MAX_REQUESTS_WITH_KEY : MAX_REQUESTS_NO_KEY;
  const now = Date.now();
  requestTimestamps = requestTimestamps.filter((t) => now - t < WINDOW_MS);

  if (requestTimestamps.length >= limit) {
    const oldest = requestTimestamps[0];
    const waitMs = WINDOW_MS - (now - oldest) + 250; // small buffer
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    return throttle();
  }
  requestTimestamps.push(now);
}

function mapSeverity(metrics: any): { severity: Severity; score: number | null; vector: string | null } {
  // NVD returns cvssMetricV31 / V30 / V2 arrays; prefer the newest available.
  const cvss31 = metrics?.cvssMetricV31?.[0]?.cvssData;
  const cvss30 = metrics?.cvssMetricV30?.[0]?.cvssData;
  const cvss2 = metrics?.cvssMetricV2?.[0]?.cvssData;
  const data = cvss31 ?? cvss30 ?? cvss2;

  if (!data) return { severity: "NONE", score: null, vector: null };

  const score: number = data.baseScore;
  let severity: Severity = "NONE";
  if (score >= 9.0) severity = "CRITICAL";
  else if (score >= 7.0) severity = "HIGH";
  else if (score >= 4.0) severity = "MEDIUM";
  else if (score > 0) severity = "LOW";

  return { severity, score, vector: data.vectorString ?? null };
}

function extractDescription(descriptions: Array<{ lang: string; value: string }>): string {
  return descriptions?.find((d) => d.lang === "en")?.value ?? "No description available.";
}

/**
 * Fetch all CVEs matching a CPE name (virtualMatchString), handling
 * pagination and self-throttling to respect NVD's rate limits.
 */
export async function fetchCvesForCpe(cpeName: string): Promise<NvdCveResult[]> {
  const results: NvdCveResult[] = [];
  let startIndex = 0;
  const resultsPerPage = 200;

  while (true) {
    await throttle();

    const url = new URL(NVD_BASE_URL);
    url.searchParams.set("virtualMatchString", cpeName);
    url.searchParams.set("resultsPerPage", String(resultsPerPage));
    url.searchParams.set("startIndex", String(startIndex));

    const headers: Record<string, string> = {};
    if (process.env.NVD_API_KEY) {
      headers["apiKey"] = process.env.NVD_API_KEY;
    }

    const res = await fetch(url.toString(), { headers });

    if (res.status === 403 || res.status === 429) {
      // Rate-limited despite our throttle (e.g. shared IP). Back off and retry once.
      await new Promise((r) => setTimeout(r, 6000));
      continue;
    }
    if (!res.ok) {
      throw new Error(`NVD API error ${res.status}: ${await res.text()}`);
    }

    const data = (await res.json()) as { vulnerabilities?: any[]; totalResults?: number };
    const vulns = data.vulnerabilities ?? [];

    for (const v of vulns) {
      const cve = v.cve;
      const { severity, score, vector } = mapSeverity(cve.metrics);
      results.push({
        id: cve.id,
        description: extractDescription(cve.descriptions),
        severity,
        cvssScore: score,
        cvssVector: vector,
        publishedAt: cve.published ?? null,
        lastModified: cve.lastModified ?? null,
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        raw: cve,
      });
    }

    const totalResults = data.totalResults ?? results.length;
    startIndex += resultsPerPage;
    if (startIndex >= totalResults || vulns.length === 0) break;
  }

  return results;
}
