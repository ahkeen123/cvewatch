import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";

export default function Login() {
  const { login, loginError } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password);
      navigate("/");
    } catch {
      // loginError is already set by the auth context
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-console-bg">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded border border-console-border bg-console-panel p-8"
      >
        <div className="mb-1 text-lg font-semibold">CVEWatch</div>
        <div className="mb-6 text-sm text-console-muted">Sign in to view your fleet's vulnerability status.</div>

        <label className="mb-1 block text-xs text-console-muted" htmlFor="email">
          Email
        </label>
        <input
          id="email"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mb-4 w-full rounded border border-console-border bg-console-bg px-3 py-2 text-sm outline-none focus:border-console-signal"
        />

        <label className="mb-1 block text-xs text-console-muted" htmlFor="password">
          Password
        </label>
        <input
          id="password"
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mb-5 w-full rounded border border-console-border bg-console-bg px-3 py-2 text-sm outline-none focus:border-console-signal"
        />

        {loginError && <div className="mb-4 text-sm text-severity-critical">{loginError}</div>}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-console-signal py-2 text-sm font-medium text-console-bg transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
