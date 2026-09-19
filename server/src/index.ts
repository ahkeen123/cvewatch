import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import cron from "node-cron";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { appRouter } from "./trpc/router.js";
import { createContext } from "./trpc/context.js";
import { refreshAllProducts } from "./services/cveCache.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT ?? 4000);

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN ?? "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.use(
  "/trpc",
  createExpressMiddleware({
    router: appRouter,
    createContext,
  })
);

// In production, serve the built React app from the same service, so one
// deploy gives you one URL instead of juggling a separate frontend host.
// (In local dev, run `npm run dev` instead, which uses Vite's own dev
// server on :5173 — this static branch is skipped there.)
const clientDist = path.resolve(__dirname, "../../client/dist");
app.use(express.static(clientDist));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/trpc") || req.path === "/health") return next();
  res.sendFile(path.join(clientDist, "index.html"));
});

app.listen(PORT, () => {
  console.log(`CVEWatch listening on http://localhost:${PORT}`);
});

// Refresh all products against NVD once a day at 03:00 server time.
cron.schedule("0 3 * * *", async () => {
  console.log("[cron] Starting scheduled NVD refresh...");
  try {
    const summary = await refreshAllProducts();
    console.log("[cron] Refresh complete:", summary);
  } catch (err) {
    console.error("[cron] Refresh failed:", err);
  }
});

// Refresh all products against NVD once a day at 03:00 server time.
// NVD's own data updates roughly every 2 hours, so daily is a reasonable
// default given the free-tier rate limit; tighten this once you have an
// API key and/or fewer products sharing the quota.
cron.schedule("0 3 * * *", async () => {
  console.log("[cron] Starting scheduled NVD refresh...");
  try {
    const summary = await refreshAllProducts();
    console.log("[cron] Refresh complete:", summary);
  } catch (err) {
    console.error("[cron] Refresh failed:", err);
  }
});
