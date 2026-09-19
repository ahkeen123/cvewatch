import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import { verifyToken, type JwtPayload } from "../middleware/auth.js";

export function createContext({ req }: CreateExpressContextOptions) {
  const authHeader = req.headers.authorization; // "Bearer <token>"
  let user: JwtPayload | null = null;

  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length);
    user = verifyToken(token);
  }

  return { user };
}

export type Context = Awaited<ReturnType<typeof createContext>>;
