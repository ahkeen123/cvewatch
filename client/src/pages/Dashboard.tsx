import { Link } from "react-router-dom";
import { trpc } from "../trpc";
import SeverityBadge from "../components/SeverityBadge";
import type { Severity } from "../types";

export default function Dashboard() {
  const productsQuery = trpc.products.list.useQuery();
  const criticalHighQuery = trpc.cves.list.useQuery({ limit: 10 });

  const products = productsQuery.data ?? [];
  const totals = products.reduce(
    (acc, p) => {
      acc.CRITICAL += p.severityCounts.CRITICAL;
      acc.HIGH += p.severityCounts.HIGH;
      acc.MEDIUM += p.severityCounts.MEDIUM;
      acc.LOW += p.severityCounts.LOW;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  );

  const urgentCves = (criticalHighQuery.data ?? []).filter(
    (c) => c.severity === "CRITICAL" || c.severity === "HIGH"
  );

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold">Dashboard</h1>
      <p className="mb-6 text-sm text-console-muted">
        Fleet status across {products.length} tracked device{products.length === 1 ? "" : "s"}.
      </p>

      <div className="mb-8 grid grid-cols-4 gap-px overflow-hidden rounded border border-console-border bg-console-border">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
          <div key={sev} className="bg-console-panel px-5 py-4">
            <div className="text-xs uppercase tracking-wide text-console-muted">{sev}</div>
            <div className="mt-1 font-mono text-2xl">{totals[sev]}</div>
          </div>
        ))}
      </div>

      <h2 className="mb-3 text-lg font-semibold">Products</h2>
      <div className="mb-8 overflow-hidden rounded border border-console-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-console-panel text-xs text-console-muted">
            <tr>
              <th className="px-4 py-2 font-normal">Product</th>
              <th className="px-4 py-2 font-normal">Vendor</th>
              <th className="px-4 py-2 font-normal">Category</th>
              <th className="px-4 py-2 font-normal">Critical</th>
              <th className="px-4 py-2 font-normal">High</th>
              <th className="px-4 py-2 font-normal">Total CVEs</th>
            </tr>
          </thead>
          <tbody>
            {products.map((p) => (
              <tr key={p.id} className="border-t border-console-border hover:bg-console-panel2">
                <td className="px-4 py-2.5">
                  <Link to={`/products/${p.id}`} className="hover:text-console-signal">
                    {p.name}
                  </Link>
                </td>
                <td className="px-4 py-2.5 text-console-muted">{p.vendor}</td>
                <td className="px-4 py-2.5 text-console-muted">{p.category}</td>
                <td className="px-4 py-2.5 font-mono">
                  {p.severityCounts.CRITICAL > 0 ? (
                    <span className="text-severity-critical">{p.severityCounts.CRITICAL}</span>
                  ) : (
                    <span className="text-console-muted">0</span>
                  )}
                </td>
                <td className="px-4 py-2.5 font-mono">
                  {p.severityCounts.HIGH > 0 ? (
                    <span className="text-severity-high">{p.severityCounts.HIGH}</span>
                  ) : (
                    <span className="text-console-muted">0</span>
                  )}
                </td>
                <td className="px-4 py-2.5 font-mono text-console-muted">{p.cveCount}</td>
              </tr>
            ))}
            {products.length === 0 && !productsQuery.isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-console-muted">
                  No products yet. Add one from the Products page.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2 className="mb-3 text-lg font-semibold">Needs attention</h2>
      <div className="overflow-hidden rounded border border-console-border">
        {urgentCves.length === 0 && (
          <div className="px-4 py-6 text-center text-sm text-console-muted">
            No critical or high-severity CVEs on record. Run a fetch from Fetch history to check for new ones.
          </div>
        )}
        {urgentCves.map((cve) => (
          <Link
            key={cve.id}
            to={`/products/${cve.matches[0]?.productId ?? ""}`}
            className="flex items-center justify-between border-t border-console-border px-4 py-3 first:border-t-0 hover:bg-console-panel2"
          >
            <div>
              <span className="font-mono text-sm">{cve.id}</span>
              <span className="ml-3 text-sm text-console-muted">
                {cve.matches.map((m) => m.product.name).join(", ")}
              </span>
            </div>
            <SeverityBadge severity={cve.severity} score={cve.cvssScore} />
          </Link>
        ))}
      </div>
    </div>
  );
}
