import { trpc } from "../trpc";
import { useAuth } from "../AuthContext";

export default function FetchHistory() {
  const { user } = useAuth();
  const utils = trpc.useUtils();
  const historyQuery = trpc.fetchHistory.list.useQuery({ limit: 100 });
  const refreshAllMutation = trpc.fetchHistory.refreshAll.useMutation({
    onSuccess: () => {
      utils.fetchHistory.list.invalidate();
      utils.products.list.invalidate();
    },
  });

  const history = historyQuery.data ?? [];

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Fetch history</h1>
          <p className="text-sm text-console-muted">Audit log of every NVD sync, per product.</p>
        </div>
        {user?.role === "ADMIN" && (
          <button
            onClick={() => refreshAllMutation.mutate()}
            disabled={refreshAllMutation.isPending}
            className="rounded bg-console-signal px-4 py-2 text-sm font-medium text-console-bg disabled:opacity-50"
          >
            {refreshAllMutation.isPending ? "Refreshing all products…" : "Refresh all products"}
          </button>
        )}
      </div>

      <div className="overflow-hidden rounded border border-console-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-console-panel text-xs text-console-muted">
            <tr>
              <th className="px-4 py-2 font-normal">Started</th>
              <th className="px-4 py-2 font-normal">Product</th>
              <th className="px-4 py-2 font-normal">Status</th>
              <th className="px-4 py-2 font-normal">Found</th>
              <th className="px-4 py-2 font-normal">New</th>
              <th className="px-4 py-2 font-normal">Error</th>
            </tr>
          </thead>
          <tbody>
            {history.map((log) => (
              <tr key={log.id} className="border-t border-console-border">
                <td className="px-4 py-2.5 text-console-muted">{new Date(log.startedAt).toLocaleString()}</td>
                <td className="px-4 py-2.5">{log.product?.name ?? "—"}</td>
                <td className="px-4 py-2.5">
                  <StatusLabel status={log.status} />
                </td>
                <td className="px-4 py-2.5 font-mono">{log.cvesFound}</td>
                <td className="px-4 py-2.5 font-mono">{log.cvesNew}</td>
                <td className="px-4 py-2.5 text-xs text-severity-critical">{log.errorMessage ?? ""}</td>
              </tr>
            ))}
            {history.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-console-muted">
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
