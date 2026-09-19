import { router } from "./trpc.js";
import { authRouter } from "./routers/auth.js";
import { productsRouter } from "./routers/products.js";
import { cvesRouter } from "./routers/cves.js";
import { fetchHistoryRouter } from "./routers/fetchHistory.js";

export const appRouter = router({
  auth: authRouter,
  products: productsRouter,
  cves: cvesRouter,
  fetchHistory: fetchHistoryRouter,
});

export type AppRouter = typeof appRouter;
