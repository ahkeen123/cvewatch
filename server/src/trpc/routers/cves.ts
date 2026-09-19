import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../trpc.js";
import { prisma } from "../../db/client.js";
import { generateFixSummary } from "../../services/aiService.js";

export const cvesRouter = router({
  list: protectedProcedure
    .input(
      z.object({
        severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]).optional(),
        productId: z.string().optional(),
        search: z.string().optional(),
        publishedAfter: z.coerce.date().optional(),
        limit: z.number().min(1).max(500).default(50),
      })
    )
    .query(async ({ input }) => {
      return prisma.cve.findMany({
        where: {
          severity: input.severity,
          matches: input.productId ? { some: { productId: input.productId } } : undefined,
          publishedAt: input.publishedAfter ? { gte: input.publishedAfter } : undefined,
          OR: input.search
            ? [
                { id: { contains: input.search } },
                { description: { contains: input.search } },
              ]
            : undefined,
        },
        include: {
          matches: { include: { product: true } },
        },
        orderBy: [{ publishedAt: "desc" }],
        take: input.limit,
      });
    }),

  byId: protectedProcedure.input(z.object({ id: z.string() })).query(async ({ input }) => {
    return prisma.cve.findUniqueOrThrow({
      where: { id: input.id },
      include: { matches: { include: { product: true } } },
    });
  }),

  acknowledge: adminProcedure
    .input(z.object({ productId: z.string(), cveId: z.string(), acknowledged: z.boolean() }))
    .mutation(async ({ input }) => {
      return prisma.productCve.update({
        where: { productId_cveId: { productId: input.productId, cveId: input.cveId } },
        data: { acknowledged: input.acknowledged },
      });
    }),

  /** Force-regenerate the AI summary, e.g. after switching AI providers. */
  regenerateSummary: adminProcedure
    .input(z.object({ cveId: z.string(), productId: z.string() }))
    .mutation(async ({ input }) => {
      const cve = await prisma.cve.findUniqueOrThrow({ where: { id: input.cveId } });
      const product = await prisma.product.findUniqueOrThrow({ where: { id: input.productId } });

      const summary = await generateFixSummary(
        { id: cve.id, description: cve.description, severity: cve.severity, cvssScore: cve.cvssScore },
        { vendor: product.vendor, model: product.model, category: product.category }
      );

      return prisma.cve.update({
        where: { id: cve.id },
        data: { aiSummary: summary, aiSummaryAt: new Date() },
      });
    }),
});
