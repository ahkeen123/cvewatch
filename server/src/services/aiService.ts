/**
 * Generates a plain-language "what this means and how to fix it" summary
 * for a CVE, tailored to the affected product.
 *
 * Provider is selected via AI_PROVIDER env var:
 *   - "anthropic": calls Claude (requires ANTHROPIC_API_KEY)
 *   - "openai":    calls OpenAI (requires OPENAI_API_KEY)
 *   - "stub":      returns a canned, clearly-labeled placeholder (default)
 *
 * You said you'd decide on a provider later — this file is the one place
 * to wire that decision up. Both real implementations are already written
 * below; flip AI_PROVIDER and set the matching key when you're ready.
 */

export interface CveForSummary {
  id: string;
  description: string;
  severity: string;
  cvssScore: number | null;
}

export interface ProductForSummary {
  vendor: string;
  model: string;
  category: string;
}

function buildPrompt(cve: CveForSummary, product: ProductForSummary): string {
  return `You are a network security analyst writing a short remediation note for an internal ops dashboard.

Product affected: ${product.vendor} ${product.model} (${product.category})
CVE: ${cve.id}
Severity: ${cve.severity}${cve.cvssScore ? ` (CVSS ${cve.cvssScore})` : ""}
Description: ${cve.description}

Write a concise summary (max 120 words) with two parts:
1. Impact: what this vulnerability actually allows an attacker to do, in plain language.
2. Recommended fix: concrete next step(s) — e.g. upgrade to a specific version if known, apply a vendor advisory, disable an affected feature, or mitigate at the network layer. If the exact fixed version isn't in the description, say to check the vendor's security advisory page rather than guessing a version number.

Do not pad with generic security advice ("always keep systems patched"). Be specific to this CVE and this product.`;
}

async function summarizeWithAnthropic(cve: CveForSummary, product: ProductForSummary): Promise<string> {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY!,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 400,
      messages: [{ role: "user", content: buildPrompt(cve, product) }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic API error ${res.status}: ${await res.text()}`);
  const data = (await res.json()) as { content?: Array<{ text?: string }> };
  return data.content?.map((b) => b.text ?? "").join("\n").trim() ?? "";
}

async function summarizeWithOpenAI(cve: CveForSummary, product: ProductForSummary): Promise<string> {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      max_tokens: 400,
      messages: [{ role: "user", content: buildPrompt(cve, product) }],
    }),
  });
  if (!res.ok) throw new Error(`OpenAI API error ${res.status}: ${await res.text()}`);
  const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
  return data.choices?.[0]?.message?.content?.trim() ?? "";
}

function stubSummary(cve: CveForSummary, product: ProductForSummary): string {
  return (
    `[STUB — no AI provider configured] This is a placeholder summary for ${cve.id} affecting ` +
    `${product.vendor} ${product.model}. Set AI_PROVIDER to "anthropic" or "openai" and supply the ` +
    `matching API key in your .env to generate a real impact + remediation summary here. ` +
    `Raw NVD description: ${cve.description.slice(0, 200)}${cve.description.length > 200 ? "…" : ""}`
  );
}

export async function generateFixSummary(
  cve: CveForSummary,
  product: ProductForSummary
): Promise<string> {
  const provider = process.env.AI_PROVIDER ?? "stub";

  try {
    if (provider === "anthropic" && process.env.ANTHROPIC_API_KEY) {
      return await summarizeWithAnthropic(cve, product);
    }
    if (provider === "openai" && process.env.OPENAI_API_KEY) {
      return await summarizeWithOpenAI(cve, product);
    }
  } catch (err) {
    console.error(`AI summary generation failed for ${cve.id}, falling back to stub:`, err);
  }

  return stubSummary(cve, product);
}
