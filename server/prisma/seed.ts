import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

// Starter fleet. CPE names are best-effort match strings used to query
// NVD's CPE dictionary — verify/adjust them against
// https://nvd.nist.gov/products/cpe/search once you're live, since vendors
// occasionally change their official CPE vendor/product strings.
const STARTER_PRODUCTS = [
  {
    name: "Alcatel-Lucent Enterprise Switch",
    vendor: "Alcatel-Lucent Enterprise",
    category: "Switch",
    model: "OmniSwitch (generic)",
    cpeName: "cpe:2.3:o:al-enterprise:omniswitch:-:*:*:*:*:*:*:*",
    notes:
      "Generic entry covering the Alcatel-Lucent OmniSwitch line. Replace the model/CPE with your exact switch model (e.g. OS6860, OS6900) once known for tighter CVE matching.",
  },
  {
    name: "PA-5260",
    vendor: "Palo Alto Networks",
    category: "Firewall",
    model: "PA-5260",
    cpeName: "cpe:2.3:h:paloaltonetworks:pa-5260:-:*:*:*:*:*:*:*",
    notes: "Next-gen firewall, PA-5200 series.",
  },
  {
    name: "PA-5220",
    vendor: "Palo Alto Networks",
    category: "Firewall",
    model: "PA-5220",
    cpeName: "cpe:2.3:h:paloaltonetworks:pa-5220:-:*:*:*:*:*:*:*",
    notes: "Next-gen firewall, PA-5200 series.",
  },
  {
    name: "Alteon 5208",
    vendor: "Radware",
    category: "Load Balancer",
    model: "Alteon 5208",
    cpeName: "cpe:2.3:h:radware:alteon_5208:-:*:*:*:*:*:*:*",
    notes: "Radware Alteon application delivery / load balancer appliance.",
  },
  {
    name: "Alteon 5260",
    vendor: "Radware",
    category: "Load Balancer",
    model: "Alteon 5260",
    cpeName: "cpe:2.3:h:radware:alteon_5260:-:*:*:*:*:*:*:*",
    notes: "Radware Alteon application delivery / load balancer appliance.",
  },
];

async function main() {
  const adminEmail = process.env.SEED_ADMIN_EMAIL ?? "admin@cvewatch.local";
  const adminPassword = process.env.SEED_ADMIN_PASSWORD ?? "ChangeMe123!";

  const passwordHash = await bcrypt.hash(adminPassword, 10);

  await prisma.user.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      email: adminEmail,
      passwordHash,
      role: "ADMIN",
    },
  });
  console.log(`Seeded admin user: ${adminEmail} (password: ${adminPassword})`);

  for (const p of STARTER_PRODUCTS) {
    const existing = await prisma.product.findFirst({
      where: { vendor: p.vendor, model: p.model },
    });
    if (existing) {
      console.log(`Skipping existing product: ${p.vendor} ${p.model}`);
      continue;
    }
    await prisma.product.create({ data: p });
    console.log(`Created product: ${p.vendor} ${p.model}`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
