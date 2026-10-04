import nodemailer from "nodemailer";
import type { NvdCveResult } from "./nvdService.js";

/**
 * Sends CVE alert emails via Gmail or Outlook SMTP, using a regular
 * mailbox + app password rather than a transactional email API.
 *
 * Required env vars:
 *   EMAIL_PROVIDER   "gmail" | "outlook"
 *   EMAIL_USER       the sending mailbox, e.g. yourname@gmail.com
 *   EMAIL_APP_PASSWORD   an app-specific password (NOT your normal login
 *                        password — see README for how to generate one)
 *   EMAIL_ALERT_TO   recipient address for CVE alerts
 *
 * If any of these are missing, alert emails are silently skipped (logged
 * as a warning) rather than crashing a refresh — a missing mail config
 * shouldn't take down CVE fetching.
 */

function getTransport() {
  const provider = process.env.EMAIL_PROVIDER?.toLowerCase();
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_APP_PASSWORD;

  if (!provider || !user || !pass) return null;

  if (provider === "gmail") {
    return nodemailer.createTransport({
      service: "gmail",
      auth: { user, pass },
    });
  }
  if (provider === "outlook") {
    return nodemailer.createTransport({
      host: "smtp.office365.com",
      port: 587,
      secure: false,
      auth: { user, pass },
    });
  }
  return null;
}

export interface AlertProductInfo {
  name: string;
  vendor: string;
  model: string;
}

/**
 * Sends one alert email summarizing newly-found CVEs for a single
 * product. Called once per product per refresh run, only for products
 * on the alert list (see ALERT_PRODUCTS in cveCache.ts) and only when
 * there's at least one new CVE to report.
 */
export async function sendCveAlertEmail(product: AlertProductInfo, newCves: NvdCveResult[]): Promise<void> {
  const transport = getTransport();
  const to = process.env.EMAIL_ALERT_TO;

  if (!transport || !to) {
    console.warn(
      `Email alert skipped for ${product.name}: EMAIL_PROVIDER/EMAIL_USER/EMAIL_APP_PASSWORD/EMAIL_ALERT_TO not fully configured.`
    );
    return;
  }

  const sorted = [...newCves].sort((a, b) => {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });

  const rows = sorted
    .map(
      (c) =>
        `<tr>
          <td style="padding:6px 12px;font-family:monospace;">${c.id}</td>
          <td style="padding:6px 12px;">${c.severity}${c.cvssScore ? ` (${c.cvssScore})` : ""}</td>
          <td style="padding:6px 12px;"><a href="${c.sourceUrl}">View on NVD</a></td>
        </tr>`
    )
    .join("\n");

  const html = `
    <div style="font-family:sans-serif;">
      <h2>New CVE(s) detected: ${product.name}</h2>
      <p>${product.vendor} · ${product.model}</p>
      <table style="border-collapse:collapse;">
        <thead>
          <tr>
            <th style="text-align:left;padding:6px 12px;">CVE</th>
            <th style="text-align:left;padding:6px 12px;">Severity</th>
            <th style="text-align:left;padding:6px 12px;">Link</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <p style="color:#666;font-size:12px;margin-top:16px;">Sent automatically by CVEWatch.</p>
    </div>
  `;

  try {
    await transport.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject: `CVEWatch: ${newCves.length} new CVE(s) for ${product.name}`,
      html,
    });
    console.log(`Alert email sent for ${product.name} (${newCves.length} new CVE(s)).`);
  } catch (err) {
    console.error(`Failed to send alert email for ${product.name}:`, err);
  }
}
