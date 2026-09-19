import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../AuthContext";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/products", label: "Products" },
  { to: "/history", label: "Fetch history" },
];

export default function Layout() {
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 flex-col border-r border-console-border bg-console-panel">
        <div className="border-b border-console-border px-5 py-5">
          <div className="text-lg font-semibold tracking-tight">CVEWatch</div>
          <div className="mt-0.5 text-xs text-console-muted">infrastructure vulnerability tracking</div>
        </div>
        <nav className="flex-1 px-2 py-4">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `mb-1 flex items-center rounded px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-console-panel2 text-console-signal"
                    : "text-console-muted hover:bg-console-panel2 hover:text-console-text"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
          {user?.role === "ADMIN" && (
            <NavLink
              to="/admin"
              className={({ isActive }) =>
                `mb-1 flex items-center rounded px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-console-panel2 text-console-signal"
                    : "text-console-muted hover:bg-console-panel2 hover:text-console-text"
                }`
              }
            >
              Admin settings
            </NavLink>
          )}
        </nav>
        <div className="border-t border-console-border px-4 py-4">
          <div className="truncate text-sm">{user?.email}</div>
          <div className="mb-3 text-xs text-console-muted">{user?.role === "ADMIN" ? "Admin" : "Viewer"}</div>
          <button
            onClick={logout}
            className="w-full rounded border border-console-border py-1.5 text-xs text-console-muted transition-colors hover:border-console-signal hover:text-console-signal"
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto px-8 py-6">
        <Outlet />
      </main>
    </div>
  );
}
