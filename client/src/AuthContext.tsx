import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { trpc, getToken, setToken, clearToken } from "./trpc";
import type { AuthUser } from "./types";

interface AuthContextValue {
  user: AuthUser | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  loginError: string | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loginError, setLoginError] = useState<string | null>(null);
  const hasToken = !!getToken();

  const meQuery = trpc.auth.me.useQuery(undefined, {
    enabled: hasToken,
    retry: false,
  });

  const loginMutation = trpc.auth.login.useMutation();
  const utils = trpc.useUtils();

  useEffect(() => {
    if (meQuery.data) {
      setUser(meQuery.data as AuthUser);
    } else if (meQuery.isError) {
      clearToken();
      setUser(null);
    }
  }, [meQuery.data, meQuery.isError]);

  async function login(email: string, password: string) {
    setLoginError(null);
    try {
      const result = await loginMutation.mutateAsync({ email, password });
      setToken(result.token);
      setUser({ userId: result.user.id, email: result.user.email, role: result.user.role });
      utils.invalidate();
    } catch (err: any) {
      setLoginError(err?.message ?? "Login failed.");
      throw err;
    }
  }

  function logout() {
    clearToken();
    setUser(null);
    utils.invalidate();
  }

  return (
    <AuthContext.Provider
      value={{ user, isLoading: hasToken && meQuery.isLoading, login, logout, loginError }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
