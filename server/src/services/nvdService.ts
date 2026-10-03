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

/** Pulls the product name out of a CPE 2.3 string, e.g.
 * "cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*"
 * -> "big-ip access policy manager" (underscores turned into spaces for a
 * natural-language keyword search; hyphens are left alone since they're
 * usually part of the real product name, e.g. "BIG-IP").
 *
 * Deliberately omits the vendor name: NVD's keywordSearch requires every
 * term to appear in the CVE description (it's an AND match), and
 * descriptions very often don't repeat the vendor name when the product
 * name is already distinctive (e.g. "Access Policy Manager" appears
 * without "F5" in the actual text), so including it just causes false
 * negatives. */
function cpeToKeywords(cpeName: string): string | null {
  const parts = cpeName.split(":");
  // cpe : 2.3 : part : vendor : product : ...
  const product = parts[4];
  if (!product) return null;
  return product.replace(/_/g, " ").trim();
}

async function nvdFetch(url: URL): Promise<Response> {
  await throttle();
  const headers: Record<string, string> = {};
  if (process.env.NVD_API_KEY) {
    headers["apiKey"] = process.env.NVD_API_KEY;
  }
  return fetch(url.toString(), { headers });
}

/** NVD rejects any pubStartDate/pubEndDate range wider than 120 days, so a
 * full year has to be requested in chunks. Returns chunk boundaries from
 * Jan 1 of `year` up to "now" (never into the future). */
function getYearDateChunks(year: number): Array<{ start: Date; end: Date }> {
  const chunks: Array<{ start: Date; end: Date }> = [];
  const yearStart = new Date(Date.UTC(year, 0, 1, 0, 0, 0, 0));
  const yearEnd = new Date(Date.UTC(year, 11, 31, 23, 59, 59, 999));
  const now = new Date();
  const hardEnd = yearEnd < now ? yearEnd : now;

  const CHUNK_DAYS = 119; // stay safely under NVD's 120-day limit
  let cursor = yearStart;
  while (cursor <= hardEnd) {
    const chunkEnd = new Date(Math.min(cursor.getTime() + CHUNK_DAYS * 86400000, hardEnd.getTime()));
    chunks.push({ start: cursor, end: chunkEnd });
    cursor = new Date(chunkEnd.getTime() + 1);
  }
  return chunks;
}

/** NVD's date params want "YYYY-MM-DDTHH:mm:ss.sss" with no trailing Z. */
function toNvdDateParam(d: Date): string {
  return d.toISOString().replace("Z", "");
}

/**
 * Fetch CVEs matching a CPE name (virtualMatchString), scoped to CVEs
 * published in `year` only, handling pagination, NVD's 120-day max date
 * range (so a full year is requested in chunks), and self-throttling to
 * respect rate limits.
 *
 * NVD's virtualMatchString lookup can return 404 even for a byte-for-byte
 * correct CPE 2.3 string — this happens for products whose CVEs are
 * catalogued with version-range match criteria rather than a plain
 * wildcard entry, which virtualMatchString doesn't always resolve. Rather
 * than fail outright, we fall back to a plain keyword search on the
 * product name extracted from the CPE string, which finds the same CVEs
 * by full-text match instead of exact CPE-criteria match.
 */
export async function fetchCvesForCpe(
  cpeName: string,
  year: number = new Date().getFullYear()
): Promise<NvdCveResult[]> {
  const chunks = getYearDateChunks(year);

  try {
    return await fetchAllChunks(chunks, (chunk, startIndex) => {
      const url = new URL(NVD_BASE_URL);
      url.searchParams.set("virtualMatchString", cpeName);
      url.searchParams.set("pubStartDate", toNvdDateParam(chunk.start));
      url.searchParams.set("pubEndDate", toNvdDateParam(chunk.end));
      url.searchParams.set("resultsPerPage", "200");
      url.searchParams.set("startIndex", String(startIndex));
      return url;
    });
  } catch (err: any) {
    if (err?.status === 404) {
      const keywords = cpeToKeywords(cpeName);
      if (keywords) {
        console.warn(
          `virtualMatchString 404 for "${cpeName}" — falling back to keyword search "${keywords}"`
        );
        return fetchAllChunks(chunks, (chunk, startIndex) => {
          const url = new URL(NVD_BASE_URL);
          url.searchParams.set("keywordSearch", keywords);
          url.searchParams.set("pubStartDate", toNvdDateParam(chunk.start));
          url.searchParams.set("pubEndDate", toNvdDateParam(chunk.end));
          url.searchParams.set("resultsPerPage", "200");
          url.searchParams.set("startIndex", String(startIndex));
          return url;
        });
      }
    }
    throw err;
  }
}

/** Walks every date chunk, paginating within each, using `buildUrl` to
 * construct the request for a given chunk + pagination offset. */
async function fetchAllChunks(
  chunks: Array<{ start: Date; end: Date }>,
  buildUrl: (chunk: { start: Date; end: Date }, startIndex: number) => URL
): Promise<NvdCveResult[]> {
  const results: NvdCveResult[] = [];

  for (const chunk of chunks) {
    let startIndex = 0;
    while (true) {
      const url = buildUrl(chunk, startIndex);
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
      startIndex += 200;
      if (startIndex >= totalResults || vulns.length === 0) break;
    }
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
