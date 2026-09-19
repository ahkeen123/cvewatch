import { createTRPCReact } from "@trpc/react-query";
import { httpBatchLink } from "@trpc/client";
import superjson from "superjson";
// Type-only import: no server code is bundled into the client, only the
// TypeScript shape of the router, which is what gives us end-to-end
// type safety on every query/mutation without hand-written API types.
import type { AppRouter } from "../../server/src/trpc/router.js";

export const trpc = createTRPCReact<AppRouter>();

const TOKEN_STORAGE_KEY = "cvewatch_token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_STORAGE_KEY);
}

export function createTrpcClient() {
  return trpc.createClient({
    links: [
      httpBatchLink({
        url: "/trpc",
        transformer: superjson,
        headers() {
          const token = getToken();
          return token ? { authorization: `Bearer ${token}` } : {};
        },
      }),
    ],
  });
}
