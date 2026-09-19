export type Role = "ADMIN" | "VIEWER";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export interface AuthUser {
  userId: string;
  email: string;
  role: Role;
}

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
