import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { trpc } from "../trpc";
import { useAuth } from "../AuthContext";
import SeverityBadge from "../components/SeverityBadge";

export default function ProductDetail() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const utils = trpc.useUtils();
  const [expandedCve, setExpandedCve] = useState<string | null>(null);

  const productQuery = trpc.products.byId.useQuery({ id: id! }, { enabled: !!id });
  const refreshMutation = trpc.products.refresh.useMutation({
    onSuccess: () => utils.products.byId.invalidate({ id: id! }),
  });
  const acknowledgeMutation = trpc.cves.acknowledge.useMutation({
    onSuccess: () => utils.products.byId.invalidate({ id: id! }),
  });
  const regenerateMutation = trpc.cves.regenerateSummary.useMutation({
    onSuccess: () => utils.products.byId.invalidate({ id: id! }),
  });

  if (productQuery.isLoading) return <div className="text-console-muted">Loading…</div>;
  if (productQuery.isError || !productQuery.data) return <div className="text-severity-critical">Product not found.</div>;

  const product = productQuery.data;

  return (
    <div>
      <Link to="/products" className="mb-4 inline-block text-sm text-console-muted hover:text-console-signal">
        ← Back to products
      </Link>

      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">{product.name}</h1>
          <p className="text-sm text-console-muted">
            {product.vendor} · {product.category}
            {product.cpeName && <span className="ml-2 font-mono text-xs">{product.cpeName}</span>}
          </p>
        </div>
        {user?.role === "ADMIN" && (
          <button
            onClick={() => refreshMutation.mutate({ id: product.id })}
            disabled={refreshMutation.isPending}
            className="rounded border border-console-border px-3 py-1.5 text-sm hover:border-console-signal hover:text-console-signal disabled:opacity-50"
          >
            {refreshMutation.isPending ? "Fetching from NVD…" : "Refresh from NVD"}
          </button>
        )}
      </div>

      {refreshMutation.data && (
        <div className="mb-4 rounded border border-console-border bg-console-panel px-4 py-2 text-sm text-console-muted">
          Found {refreshMutation.data.cvesFound} CVE(s), {refreshMutation.data.cvesNew} new.
        </div>
      )}

      <h2 className="mb-3 text-lg font-semibold">Matched CVEs ({product.matches.length})</h2>
      <div className="mb-8 divide-y divide-console-border rounded border border-console-border">
        {product.matches.length === 0 && (
          <div className="px-4 py-6 text-center text-sm text-console-muted">
            No CVEs matched yet. {user?.role === "ADMIN" ? "Click Refresh from NVD to check." : "Ask an admin to run a refresh."}
          </div>
        )}
        {product.matches.map((m) => {
          const cve = m.cve;
          const isOpen = expandedCve === cve.id;
          return (
            <div key={cve.id} className="bg-console-panel">
              <button
                onClick={() => setExpandedCve(isOpen ? null : cve.id)}
                className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-console-panel2"
              >
                <div className="flex items-center gap-4">
                  <span className="font-mono text-sm">{cve.id}</span>
                  {m.acknowledged && (
                    <span className="text-xs text-console-muted">acknowledged</span>
                  )}
                </div>
                <SeverityBadge severity={cve.severity} score={cve.cvssScore} />
              </button>
              {isOpen && (
                <div className="border-t border-console-border px-4 py-4">
                  <p className="mb-3 text-sm text-console-text">{cve.description}</p>

                  <div className="mb-3 rounded border border-console-border bg-console-bg p-3">
                    <div className="mb-1 flex items-center justify-between">
                      <div className="text-xs uppercase tracking-wide text-console-muted">AI fix summary</div>
                      {user?.role === "ADMIN" && (
                        <button
                          onClick={() => regenerateMutation.mutate({ cveId: cve.id, productId: product.id })}
                          disabled={regenerateMutation.isPending}
                          className="text-xs text-console-muted hover:text-console-signal"
                        >
                          Regenerate
                        </button>
                      )}
                    </div>
                    <p className="text-sm text-console-text">
                      {cve.aiSummary ?? "No summary generated yet."}
                    </p>
                  </div>

                  <div className="flex items-center justify-between text-xs text-console-muted">
                    <div>
                      {cve.sourceUrl && (
                        <a href={cve.sourceUrl} target="_blank" rel="noreferrer" className="hover:text-console-signal">
                          View on NVD ↗
                        </a>
                      )}
                    </div>
                    {user?.role === "ADMIN" && (
                      <button
                        onClick={() =>
                          acknowledgeMutation.mutate({
                            productId: product.id,
                            cveId: cve.id,
                            acknowledged: !m.acknowledged,
                          })
                        }
                        className="hover:text-console-signal"
                      >
                        {m.acknowledged ? "Mark unacknowledged" : "Mark acknowledged"}
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <h2 className="mb-3 text-lg font-semibold">Recent fetch history</h2>
      <div className="overflow-hidden rounded border border-console-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-console-panel text-xs text-console-muted">
            <tr>
              <th className="px-4 py-2 font-normal">Started</th>
              <th className="px-4 py-2 font-normal">Status</th>
              <th className="px-4 py-2 font-normal">Found</th>
              <th className="px-4 py-2 font-normal">New</th>
            </tr>
          </thead>
          <tbody>
            {product.fetchLogs.map((log) => (
              <tr key={log.id} className="border-t border-console-border">
                <td className="px-4 py-2.5 text-console-muted">{new Date(log.startedAt).toLocaleString()}</td>
                <td className="px-4 py-2.5">
                  <StatusLabel status={log.status} />
                </td>
                <td className="px-4 py-2.5 font-mono">{log.cvesFound}</td>
                <td className="px-4 py-2.5 font-mono">{log.cvesNew}</td>
              </tr>
            ))}
            {product.fetchLogs.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-4 text-center text-console-muted">
                  No fetches recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusLabel({ status }: { status: string }) {
  const color =
    status === "SUCCESS" ? "text-severity-low" : status === "PARTIAL" ? "text-severity-medium" : "text-severity-critical";
  return <span className={color}>{status}</span>;
}
