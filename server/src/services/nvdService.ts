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

/** Known acronyms vendors use INSTEAD OF the full product name inside CVE
 * descriptions — e.g. HPE/Aruba write "CPPM" throughout ClearPass Policy
 * Manager advisories and never spell out the full name. An exact-phrase
 * search for the full product name finds nothing in those cases, so for
 * known products we also try the acronym. This list is necessarily
 * incomplete — add to it as new gaps like this turn up. */
const PRODUCT_ACRONYMS: Record<string, string[]> = {
  clearpass_policy_manager: ["CPPM"],
};

/** Pulls the product name out of a CPE 2.3 string and returns one or more
 * keyword phrases to try, e.g.
 * "cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*"
 * -> ["big-ip access policy manager"]
 * "cpe:2.3:a:arubanetworks:clearpass_policy_manager:*:*:*:*:*:*:*:*"
 * -> ["clearpass policy manager", "CPPM"]
 *
 * The full-name phrase has underscores turned into spaces for a
 * natural-language keyword search (hyphens are left alone since they're
 * usually part of the real product name, e.g. "BIG-IP"), and deliberately
 * omits the vendor name: descriptions very often don't repeat the vendor
 * name when the product name is already distinctive, so including it
 * just adds noise. Every phrase is tried with keywordExactMatch=true
 * (see fetchAllChunks' callers) — without it, NVD treats a multi-word
 * keywordSearch as an OR across every individual word, which is far too
 * broad (e.g. "manager" alone matches almost anything) and both buries
 * real matches and pulls in unrelated CVEs. */
function cpeToKeywords(cpeName: string): string[] | null {
  const parts = cpeName.split(":");
  // cpe : 2.3 : part : vendor : product : ...
  const product = parts[4];
  if (!product) return null;
  const fullName = product.replace(/_/g, " ").trim();
  const acronyms = PRODUCT_ACRONYMS[product] ?? [];
  return [fullName, ...acronyms];
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
 * Fetch CVEs for a CPE, scoped to CVEs published in `year` only, handling
 * pagination, NVD's 120-day max date range (so a full year is requested
 * in chunks), and self-throttling to respect rate limits.
 *
 * We always run BOTH of NVD's two independent lookup methods and merge
 * the results, rather than treating one as a fallback for the other:
 *
 *  1. virtualMatchString — matches against NVD's official, analyst-
 *     assigned CPE applicability data. This is the most precise method
 *     when it has data, but it can come back genuinely empty (as a
 *     normal 200 response, not an error) for CVEs NVD hasn't finished
 *     analyzing yet — which, given NVD's well-documented analysis
 *     backlog, can mean weeks of lag even for very real, actively
 *     exploited CVEs.
 *  2. keywordSearch (exact phrase) — matches against the free-text
 *     description instead, which is populated the moment a CVE is
 *     published, so it doesn't have that lag. It can miss things too,
 *     though: some vendors (HPE/Aruba in particular) write only an
 *     acronym like "CPPM" in the description and never spell out the
 *     full product name, so we also try any known acronym for the
 *     product (see PRODUCT_ACRONYMS).
 *
 * Relying on either method alone misses real CVEs the other would have
 * caught, so we query both and dedupe by CVE id. Any single request that
 * fails (NVD returns 404/500/etc. for reasons that don't always mean
 * "nothing found" vs. "something's wrong," and it isn't reliably
 * possible to tell which from outside) is logged and skipped rather than
 * aborting the whole fetch, so one bad request doesn't erase everything
 * the other queries did find.
 */
export async function fetchCvesForCpe(
  cpeName: string,
  year: number = new Date().getFullYear()
): Promise<NvdCveResult[]> {
  const chunks = getYearDateChunks(year);
  const byId = new Map<string, NvdCveResult>();

  const virtualMatches = await fetchAllChunks(cpeName, chunks, (chunk, startIndex) => {
    const url = new URL(NVD_BASE_URL);
    url.searchParams.set("virtualMatchString", cpeName);
    url.searchParams.set("pubStartDate", toNvdDateParam(chunk.start));
    url.searchParams.set("pubEndDate", toNvdDateParam(chunk.end));
    url.searchParams.set("resultsPerPage", "200");
    url.searchParams.set("startIndex", String(startIndex));
    return url;
  });
  for (const m of virtualMatches) byId.set(m.id, m);

  const phrases = cpeToKeywords(cpeName) ?? [];
  for (const phrase of phrases) {
    // keywordExactMatch=true turned out to be unreliable on NVD's end —
    // it 404s even for simple, verifiably-correct multi-word phrases,
    // independent of any date filtering. So instead: fetch broadly
    // (every CVE containing ANY of the words, which is what NVD does
    // without that flag) and do our own exact-phrase-equivalent
    // filtering client-side, requiring every significant word to
    // actually appear in the description. This gets the precision we
    // wanted without depending on NVD's broken flag.
    const significantWords = phrase
      .toLowerCase()
      .split(/[\s-]+/)
      .filter((w) => w.length > 2); // drop tiny words that aren't meaningfully distinctive

    const candidates = await fetchAllChunks(cpeName, chunks, (chunk, startIndex) => {
      const url = new URL(NVD_BASE_URL);
      url.searchParams.set("keywordSearch", phrase);
      url.searchParams.set("pubStartDate", toNvdDateParam(chunk.start));
      url.searchParams.set("pubEndDate", toNvdDateParam(chunk.end));
      url.searchParams.set("resultsPerPage", "200");
      url.searchParams.set("startIndex", String(startIndex));
      return url;
    });

    for (const c of candidates) {
      const text = c.description.toLowerCase();
      if (significantWords.every((w) => text.includes(w))) {
        byId.set(c.id, c);
      }
    }
  }

  return Array.from(byId.values());
}

/** Walks every date chunk, paginating within each, using `buildUrl` to
 * construct the request for a given chunk + pagination offset. A request
 * that comes back non-ok is logged and treated as "0 results for this
 * chunk" rather than aborting the whole fetch — see fetchCvesForCpe's
 * doc comment for why NVD's errors here can't be reliably distinguished
 * from legitimate empty results. */
async function fetchAllChunks(
  cpeName: string,
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
        console.warn(
          `NVD request failed (${res.status}) for "${cpeName}", chunk ${toNvdDateParam(chunk.start)}–${toNvdDateParam(
            chunk.end
          )} — treating as 0 results for this chunk. URL: ${url.toString()}`
        );
        break;
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
