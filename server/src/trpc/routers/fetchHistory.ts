import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../trpc.js";
import { prisma } from "../../db/client.js";
import { refreshAllProducts } from "../../services/cveCache.js";

export const fetchHistoryRouter = router({
  list: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(200).default(50) }))
    .query(async ({ input }) => {
      return prisma.fetchHistory.findMany({
        include: { product: true },
        orderBy: { startedAt: "desc" },
        take: input.limit,
      });
    }),

  /** Admin-triggered refresh of every product's CVEs against NVD. */
  refreshAll: adminProcedure.mutation(async () => {
    return refreshAllProducts();
  }),
});
