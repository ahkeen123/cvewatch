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

/** Pulls vendor + product out of a CPE 2.3 string, e.g.
 * "cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*"
 * -> "f5 big ip access policy manager" (underscores turned into spaces
 * for a natural-language keyword search). */
function cpeToKeywords(cpeName: string): string | null {
  const parts = cpeName.split(":");
  // cpe : 2.3 : part : vendor : product : ...
  const vendor = parts[3];
  const product = parts[4];
  if (!vendor || !product) return null;
  return `${vendor} ${product}`.replace(/_/g, " ").trim();
}

async function nvdFetch(url: URL): Promise<Response> {
  await throttle();
  const headers: Record<string, string> = {};
  if (process.env.NVD_API_KEY) {
    headers["apiKey"] = process.env.NVD_API_KEY;
  }
  return fetch(url.toString(), { headers });
}

/**
 * Fetch all CVEs matching a CPE name (virtualMatchString), handling
 * pagination and self-throttling to respect NVD's rate limits.
 *
 * NVD's virtualMatchString lookup can return 404 even for a byte-for-byte
 * correct CPE 2.3 string — this happens for products whose CVEs are
 * catalogued with version-range match criteria rather than a plain
 * wildcard entry, which virtualMatchString doesn't always resolve. Rather
 * than fail outright, we fall back to a plain keyword search on the
 * vendor/product name extracted from the CPE string, which finds the same
 * CVEs by full-text match instead of exact CPE-criteria match.
 */
export async function fetchCvesForCpe(cpeName: string): Promise<NvdCveResult[]> {
  try {
    return await fetchByVirtualMatchString(cpeName);
  } catch (err: any) {
    if (err?.status === 404) {
      const keywords = cpeToKeywords(cpeName);
      if (keywords) {
        console.warn(
          `virtualMatchString 404 for "${cpeName}" — falling back to keyword search "${keywords}"`
        );
        return fetchByKeywordSearch(keywords);
      }
    }
    throw err;
  }
}

async function fetchByVirtualMatchString(cpeName: string): Promise<NvdCveResult[]> {
  const results: NvdCveResult[] = [];
  let startIndex = 0;
  const resultsPerPage = 200;

  while (true) {
    const url = new URL(NVD_BASE_URL);
    url.searchParams.set("virtualMatchString", cpeName);
    url.searchParams.set("resultsPerPage", String(resultsPerPage));
    url.searchParams.set("startIndex", String(startIndex));

    const res = await nvdFetch(url);

    if (res.status === 403 || res.status === 429) {
      await new Promise((r) => setTimeout(r, 6000));
      continue;
    }
    if (!res.ok) {
      const error: any = new Error(`NVD API error ${res.status}: ${await res.text()}`);
      error.status = res.status;
      throw error;
    }

    const data = (await res.json()) as { vulnerabilities?: Array<{ cve: any }>; totalResults?: number };
    const vulns = data.vulnerabilities ?? [];

    for (const v of vulns) {
      results.push(mapNvdEntry(v.cve));
    }

    const totalResults = data.totalResults ?? results.length;
    startIndex += resultsPerPage;
    if (startIndex >= totalResults || vulns.length === 0) break;
  }

  return results;
}

async function fetchByKeywordSearch(keywords: string): Promise<NvdCveResult[]> {
  const results: NvdCveResult[] = [];
  let startIndex = 0;
  const resultsPerPage = 200;
  const maxResults = 500; // keyword search can be broad; cap it to stay reasonable

  while (true) {
    const url = new URL(NVD_BASE_URL);
    url.searchParams.set("keywordSearch", keywords);
    url.searchParams.set("resultsPerPage", String(resultsPerPage));
    url.searchParams.set("startIndex", String(startIndex));

    const res = await nvdFetch(url);

    if (res.status === 403 || res.status === 429) {
      await new Promise((r) => setTimeout(r, 6000));
      continue;
    }
    if (!res.ok) {
      const error: any = new Error(`NVD API error ${res.status}: ${await res.text()}`);
      error.status = res.status;
      throw error;
    }

    const data = (await res.json()) as { vulnerabilities?: Array<{ cve: any }>; totalResults?: number };
    const vulns = data.vulnerabilities ?? [];

    for (const v of vulns) {
      results.push(mapNvdEntry(v.cve));
    }

    const totalResults = Math.min(data.totalResults ?? results.length, maxResults);
    startIndex += resultsPerPage;
    if (startIndex >= totalResults || vulns.length === 0 || results.length >= maxResults) break;
  }

  return results;
}

function mapNvdEntry(cve: any): NvdCveResult {
  const { severity, score, vector } = mapSeverity(cve.metrics);
  return {
    id: cve.id,
    description: extractDescription(cve.descriptions),
    severity,
    cvssScore: score,
    cvssVector: vector,
    publishedAt: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    raw: cve,
  };
}
