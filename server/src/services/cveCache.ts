import { prisma } from "../db/client.js";
import { fetchCvesForCpe } from "./nvdService.js";
import { generateFixSummary } from "./aiService.js";

/**
 * Refreshes cached CVE data for a single product: queries NVD by the
 * product's CPE name, upserts each CVE into the local cache, links it to
 * the product, and kicks off an AI summary for newly-discovered
 * HIGH/CRITICAL CVEs (kept synchronous-but-best-effort so a slow AI call
 * never blocks the fetch loop for long — failures fall back to a stub).
 */
export async function refreshProduct(productId: string) {
  const product = await prisma.product.findUniqueOrThrow({ where: { id: productId } });

  const fetchLog = await prisma.fetchHistory.create({
    data: { productId: product.id, status: "SUCCESS" },
  });

  if (!product.cpeName) {
    await prisma.fetchHistory.update({
      where: { id: fetchLog.id },
      data: {
        finishedAt: new Date(),
        status: "FAILED",
        errorMessage: "Product has no CPE name configured — cannot query NVD.",
      },
    });
    return { cvesFound: 0, cvesNew: 0 };
  }

  try {
    const nvdResults = await fetchCvesForCpe(product.cpeName);
    let cvesNew = 0;

    for (const r of nvdResults) {
      const existing = await prisma.cve.findUnique({ where: { id: r.id } });

      await prisma.cve.upsert({
        where: { id: r.id },
        create: {
          id: r.id,
          description: r.description,
          severity: r.severity,
          cvssScore: r.cvssScore,
          cvssVector: r.cvssVector,
          publishedAt: r.publishedAt ? new Date(r.publishedAt) : null,
          lastModified: r.lastModified ? new Date(r.lastModified) : null,
          sourceUrl: r.sourceUrl,
          rawNvdJson: JSON.stringify(r.raw),
        },
        update: {
          description: r.description,
          severity: r.severity,
          cvssScore: r.cvssScore,
          cvssVector: r.cvssVector,
          lastModified: r.lastModified ? new Date(r.lastModified) : null,
          rawNvdJson: JSON.stringify(r.raw),
          cachedAt: new Date(),
        },
      });

      await prisma.productCve.upsert({
        where: { productId_cveId: { productId: product.id, cveId: r.id } },
        create: { productId: product.id, cveId: r.id },
        update: {},
      });

      const isNew = !existing;
      if (isNew) cvesNew++;

      // Generate an AI summary for newly-seen, meaningfully-severe CVEs.
      if (isNew && (r.severity === "CRITICAL" || r.severity === "HIGH")) {
        try {
          const summary = await generateFixSummary(
            { id: r.id, description: r.description, severity: r.severity, cvssScore: r.cvssScore },
            { vendor: product.vendor, model: product.model, category: product.category }
          );
          await prisma.cve.update({
            where: { id: r.id },
            data: { aiSummary: summary, aiSummaryAt: new Date() },
          });
        } catch (err) {
          console.error(`AI summary failed for ${r.id}:`, err);
        }
      }
    }

    await prisma.fetchHistory.update({
      where: { id: fetchLog.id },
      data: {
        finishedAt: new Date(),
        status: "SUCCESS",
        cvesFound: nvdResults.length,
        cvesNew,
      },
    });

    return { cvesFound: nvdResults.length, cvesNew };
  } catch (err: any) {
    await prisma.fetchHistory.update({
      where: { id: fetchLog.id },
      data: {
        finishedAt: new Date(),
        status: "FAILED",
        errorMessage: err?.message ?? String(err),
      },
    });
    throw err;
  }
}

/** Refreshes every product sequentially (NVD rate limits punish parallelism). */
export async function refreshAllProducts() {
  const products = await prisma.product.findMany();
  const summary: Record<string, { cvesFound: number; cvesNew: number } | { error: string }> = {};

  for (const product of products) {
    try {
      summary[product.id] = await refreshProduct(product.id);
    } catch (err: any) {
      summary[product.id] = { error: err?.message ?? String(err) };
    }
  }
  return summary;
}
