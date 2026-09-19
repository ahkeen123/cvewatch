import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { trpc } from "../trpc";
import { useAuth } from "../AuthContext";

const emptyForm = { name: "", vendor: "", category: "", model: "", cpeName: "", notes: "" };

export default function Products() {
  const { user } = useAuth();
  const utils = trpc.useUtils();
  const productsQuery = trpc.products.list.useQuery();
  const createMutation = trpc.products.create.useMutation({
    onSuccess: () => utils.products.list.invalidate(),
  });
  const deleteMutation = trpc.products.delete.useMutation({
    onSuccess: () => utils.products.list.invalidate(),
  });
  const refreshMutation = trpc.products.refresh.useMutation({
    onSuccess: () => {
      utils.products.list.invalidate();
      utils.fetchHistory.list.invalidate();
    },
  });

  const [form, setForm] = useState(emptyForm);
  const [showForm, setShowForm] = useState(false);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    await createMutation.mutateAsync({
      name: form.name,
      vendor: form.vendor,
      category: form.category,
      model: form.model,
      cpeName: form.cpeName || undefined,
      notes: form.notes || undefined,
    });
    setForm(emptyForm);
    setShowForm(false);
  }

  const products = productsQuery.data ?? [];

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Products</h1>
          <p className="text-sm text-console-muted">Devices tracked for CVE matches against NVD.</p>
        </div>
        {user?.role === "ADMIN" && (
          <button
            onClick={() => setShowForm((s) => !s)}
            className="rounded border border-console-border px-3 py-1.5 text-sm hover:border-console-signal hover:text-console-signal"
          >
            {showForm ? "Cancel" : "Add product"}
          </button>
        )}
      </div>

      {showForm && (
        <form
          onSubmit={handleCreate}
          className="mb-6 grid grid-cols-2 gap-4 rounded border border-console-border bg-console-panel p-5"
        >
          <Field label="Display name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} required />
          <Field label="Vendor" value={form.vendor} onChange={(v) => setForm({ ...form, vendor: v })} required />
          <Field label="Category" value={form.category} onChange={(v) => setForm({ ...form, category: v })} required placeholder="Switch / Firewall / Load Balancer" />
          <Field label="Model" value={form.model} onChange={(v) => setForm({ ...form, model: v })} required />
          <div className="col-span-2">
            <Field
              label="CPE name (used to query NVD)"
              value={form.cpeName}
              onChange={(v) => setForm({ ...form, cpeName: v })}
              placeholder="cpe:2.3:h:vendor:model:-:*:*:*:*:*:*:*"
              mono
            />
          </div>
          <div className="col-span-2">
            <label className="mb-1 block text-xs text-console-muted">Notes</label>
            <textarea
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
              className="w-full rounded border border-console-border bg-console-bg px-3 py-2 text-sm outline-none focus:border-console-signal"
              rows={2}
            />
          </div>
          <div className="col-span-2">
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="rounded bg-console-signal px-4 py-2 text-sm font-medium text-console-bg disabled:opacity-50"
            >
              {createMutation.isPending ? "Adding…" : "Add product"}
            </button>
          </div>
        </form>
      )}

      <div className="overflow-hidden rounded border border-console-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-console-panel text-xs text-console-muted">
            <tr>
              <th className="px-4 py-2 font-normal">Name</th>
              <th className="px-4 py-2 font-normal">Vendor</th>
              <th className="px-4 py-2 font-normal">Category</th>
              <th className="px-4 py-2 font-normal">CVEs</th>
              <th className="px-4 py-2 font-normal">Last updated</th>
              {user?.role === "ADMIN" && <th className="px-4 py-2 font-normal">Actions</th>}
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
                <td className="px-4 py-2.5 font-mono">{p.cveCount}</td>
                <td className="px-4 py-2.5 text-console-muted">
                  {new Date(p.updatedAt).toLocaleDateString()}
                </td>
                {user?.role === "ADMIN" && (
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => refreshMutation.mutate({ id: p.id })}
                      disabled={refreshMutation.isPending}
                      className="mr-3 text-xs text-console-muted hover:text-console-signal disabled:opacity-50"
                    >
                      Refresh
                    </button>
                    <button
                      onClick={() => {
                        if (confirm(`Remove ${p.name}?`)) deleteMutation.mutate({ id: p.id });
                      }}
                      className="text-xs text-console-muted hover:text-severity-critical"
                    >
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  required,
  placeholder,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <div>
      <label className="mb-1 block text-xs text-console-muted">{label}</label>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        placeholder={placeholder}
        className={`w-full rounded border border-console-border bg-console-bg px-3 py-2 text-sm outline-none focus:border-console-signal ${
          mono ? "font-mono" : ""
        }`}
      />
    </div>
  );
}
