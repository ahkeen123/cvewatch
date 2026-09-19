import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../trpc.js";
import { prisma } from "../../db/client.js";
import { refreshProduct } from "../../services/cveCache.js";

const productInput = z.object({
  name: z.string().min(1),
  vendor: z.string().min(1),
  category: z.string().min(1),
  model: z.string().min(1),
  cpeName: z.string().optional(),
  notes: z.string().optional(),
});

export const productsRouter = router({
  list: protectedProcedure.query(async () => {
    const products = await prisma.product.findMany({
      orderBy: [{ vendor: "asc" }, { model: "asc" }],
      include: {
        matches: {
          include: { cve: true },
        },
      },
    });

    // Surface a quick severity summary per product for the dashboard.
    return products.map((p) => {
      const bySeverity: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE", number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        NONE: 0,
      };
      for (const m of p.matches) bySeverity[m.cve.severity]++;
      return {
        id: p.id,
        name: p.name,
        vendor: p.vendor,
        category: p.category,
        model: p.model,
        cpeName: p.cpeName,
        notes: p.notes,
        updatedAt: p.updatedAt,
        cveCount: p.matches.length,
        severityCounts: bySeverity,
      };
    });
  }),

  byId: protectedProcedure.input(z.object({ id: z.string() })).query(async ({ input }) => {
    return prisma.product.findUniqueOrThrow({
      where: { id: input.id },
      include: {
        matches: {
          include: { cve: true },
          orderBy: { matchedAt: "desc" },
        },
        fetchLogs: {
          orderBy: { startedAt: "desc" },
          take: 10,
        },
      },
    });
  }),

  create: adminProcedure.input(productInput).mutation(async ({ input }) => {
    return prisma.product.create({ data: input });
  }),

  update: adminProcedure
    .input(productInput.partial().extend({ id: z.string() }))
    .mutation(async ({ input }) => {
      const { id, ...data } = input;
      return prisma.product.update({ where: { id }, data });
    }),

  delete: adminProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {
    await prisma.product.delete({ where: { id: input.id } });
    return { success: true };
  }),

  /** Admin-triggered manual refresh against NVD for a single product. */
  refresh: adminProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {
    return refreshProduct(input.id);
  }),
});
