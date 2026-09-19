# CVEWatch

A vulnerability-tracking dashboard for network infrastructure. Tracks CVEs
from NVD against a fleet of devices, caches results in a database, and uses
an LLM to generate plain-language fix recommendations.

Seeded out of the box with:
- Alcatel-Lucent Enterprise switch (generic — tighten the model once you know it)
- Palo Alto Networks PA-5260
- Palo Alto Networks PA-5220
- Radware Alteon 5208
- Radware Alteon 5260

## Architecture

```
cvewatch/
├── server/         Express + tRPC API, Prisma ORM, NVD + AI service layer
│   ├── prisma/      schema.prisma (data model) + seed.ts (starter products/admin user)
│   └── src/
│       ├── services/   nvdService.ts (NVD API client), aiService.ts (Claude/OpenAI/stub),
│       │               cveCache.ts (orchestrates fetch → cache → match → summarize)
│       ├── trpc/       routers for auth, products, cves, fetchHistory
│       └── middleware/ JWT auth
└── client/         React 19 + TypeScript + Tailwind, talks to the server via tRPC
    └── src/
        ├── pages/       Dashboard, Products, ProductDetail, FetchHistory, AdminSettings, Login
        └── components/  Layout (nav), SeverityBadge
```

**Why this can't be a single HTML file:** NVD does not send CORS headers
permitting browser requests, so fetching CVE data requires a server. That
server also caches results in a database (NVD's API is rate-limited: 5
requests/30s without a key), calls out to an LLM for fix summaries, and
enforces admin-vs-viewer permissions — none of which a static page can do
on its own.

## 1. Install dependencies

```bash
npm install
```

This installs both `server` and `client` workspaces from the root.

## 2. Set up your database

You need a real MySQL or TiDB instance — the app won't run without one.
Easiest free options:
- **TiDB Serverless** (MySQL-compatible, generous free tier): https://tidbcloud.com
- **PlanetScale**, **Railway MySQL**, or a local `mysql` install all work too.

Copy the env template and fill in `DATABASE_URL`:

```bash
cp .env.example server/.env
# edit server/.env — at minimum set DATABASE_URL
```

Then push the schema and seed starter data:

```bash
npm run db:push
npm run db:seed
```

`db:seed` creates an admin user. Check the console output (or your `.env`)
for the email/password — default is `admin@cvewatch.local` / `ChangeMe123!`.
**Change that password** by re-running seed with different
`SEED_ADMIN_PASSWORD` values, or add a "change password" flow before going
to production.

## 3. (Optional) Set up NVD and AI keys

Both work without configuration — NVD just runs at a slower rate limit, and
AI summaries fall back to a labeled stub — but for real use:

- **NVD_API_KEY**: request one free at https://nvd.nist.gov/developers/request-an-api-key
  (raises the limit from 5 to 50 requests/30s)
- **AI_PROVIDER** + matching key: set `AI_PROVIDER=anthropic` with
  `ANTHROPIC_API_KEY=sk-ant-...`, or `AI_PROVIDER=openai` with
  `OPENAI_API_KEY=sk-...`

## 4. Run it

```bash
npm run dev
```

This starts the API on `http://localhost:4000` and the frontend on
`http://localhost:5173` (Vite proxies `/trpc` calls to the API). Log in with
the seeded admin account, then:

1. Go to **Products** — your five starter devices are already there.
2. Open a product and click **Refresh from NVD** to pull its CVEs.
3. Any newly-discovered CRITICAL/HIGH CVE automatically gets an AI summary.
4. Use **Fetch history** → **Refresh all products** to sync everything at once.

A daily cron job (3am server time) also refreshes every product
automatically — see `server/src/index.ts` if you want to change the
schedule or frequency.

## Roles

- **ADMIN**: add/edit/remove products, trigger NVD refreshes, regenerate AI
  summaries, acknowledge CVEs.
- **VIEWER**: read-only access to the dashboard, products, and CVE detail.

Create additional users directly in the database for now (via
`npm run db:studio`, which opens Prisma's data browser) — there's no
self-service signup, intentionally, since this manages security data.

## Verifying your CPE names

The seeded `cpeName` values are best-effort matches. Before relying on this
in production, verify each one against NVD's CPE dictionary
(https://nvd.nist.gov/products/cpe/search) and correct any that don't match
your exact hardware/firmware, especially the Alcatel entry, which is
intentionally generic until you specify an exact switch model (e.g. OS6860,
OS6900).

## Deploying

This repo is unopinionated about hosting. Common paths:
- **Server**: any Node host (Railway, Render, Fly.io, a VPS). Run
  `npm run build -w server && npm run start -w server`.
- **Client**: any static host (Vercel, Netlify, Cloudflare Pages). Run
  `npm run build -w client` and serve `client/dist`. Point it at your
  deployed API by setting the tRPC client's URL (currently a relative
  `/trpc`, which assumes the client and API share a domain via a reverse
  proxy — adjust `client/src/trpc.ts` if you're hosting them separately).
- **Database**: TiDB Serverless or any managed MySQL.

If you're deploying to your existing Manus site
(`cvewatch-a7a3qvfx.manus.space`), follow Manus's own deployment flow for a
Node/Express + static-frontend project — this repo is the source, Manus
handles the hosting.
