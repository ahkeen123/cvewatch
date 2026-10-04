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
//
// Vite's JS/CSS bundles are named with a content hash (e.g.
// index-a1b2c3.js), so they're safe to cache aggressively — a new build
// gets a new filename automatically. index.html is the opposite: it's
// always named the same, and it's the thing that tells the browser which
// hashed bundle to load. If index.html itself gets cached anywhere (the
// browser, or a CDN/proxy in front of this app), visitors keep loading
// the OLD bundle forever even after a successful new deploy. So we
// explicitly forbid caching index.html while leaving the default
// (cacheable) behavior in place for every hashed asset.
const clientDist = path.resolve(__dirname, "../../client/dist");
app.use(express.static(clientDist, { index: false }));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/trpc") || req.path === "/health") return next();
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(path.join(clientDist, "index.html"));
});

app.listen(PORT, () => {
  console.log(`CVEWatch listening on http://localhost:${PORT}`);
});

// Refresh every product automatically, once a day at 7:00 AM Singapore
// time — runs on the server regardless of whether anyone has the app
// open in a browser. The `timezone` option handles the UTC conversion
// for us, so this stays correct even across daylight-saving changes
// elsewhere (Singapore doesn't observe DST, but this is the right way
// to express "7am local time" either way).
cron.schedule(
  "0 7 * * *",
  async () => {
    console.log("[cron] Starting scheduled daily NVD refresh (7am Asia/Singapore)...");
    try {
      const summary = await refreshAllProducts();
      console.log("[cron] Refresh complete:", summary);
    } catch (err) {
      console.error("[cron] Refresh failed:", err);
    }
  },
  { timezone: "Asia/Singapore" }
);
