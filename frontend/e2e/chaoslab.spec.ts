import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshotsDir = path.resolve(__dirname, "..", "..", "docs", "screenshots");
const shouldCapture = process.env.CAPTURE_SCREENSHOTS === "1";

async function maybeCapture(page: Page, filename: string) {
  if (!shouldCapture) return;
  fs.mkdirSync(screenshotsDir, { recursive: true });
  await page.screenshot({ path: path.join(screenshotsDir, filename), fullPage: false });
}

test.describe.serial("CHAOS LAB Full Operations Console E2E", () => {
  let context: BrowserContext;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({
      baseURL: "http://127.0.0.1:5174",
      viewport: { width: 1440, height: 900 },
      acceptDownloads: true,
    });
    page = await context.newPage();
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("1. Login, safety banner, environment overview, and asset telemetry", async () => {
    await page.goto("/");
    await expect(page.getByText("CHAOS LAB")).toBeVisible();

    await page.getByRole("button", { name: "Analyst", exact: true }).click();
    await page.getByRole("button", { name: /Sign In to Operations Console/i }).click();

    await expect(
      page.getByText("OFFLINE SIMULATION · modeled data only · no live systems contacted")
    ).toBeVisible();

    await page.getByRole("button", { name: "Overview", exact: true }).click();
    await expect(page.getByText("Environment Overview")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Meridian Freight" })).toBeVisible();
    await expect(page.locator(".mc-panel", { hasText: "Assets / Zones" })).toContainText("15");
    await maybeCapture(page, "overview.png");

    await page.getByRole("button", { name: "Assets", exact: true }).click();
    await page.getByPlaceholder("Search key, name, owner, IP…").fill("db-01");
    await expect(page.getByText("Customer Orders Database").first()).toBeVisible();
    await page.getByText("Customer Orders Database").first().click();
    await expect(page.getByText("Asset Telemetry & Provenance")).toBeVisible();
    await expect(page.getByText("EV-014").first()).toBeVisible();
  });

  test("2. Attack Paths sweep and Cytoscape topology canvas with overlays", async () => {
    await page.getByRole("button", { name: "Attack Paths", exact: true }).click();
    await expect(page.getByText("Multi-Target Attack Path Sweep")).toBeVisible();
    await expect(page.getByText("headline:")).toBeVisible();
    await expect(page.getByText("22.0").first()).toBeVisible();

    const canvas = page.locator("canvas").first();
    await expect(canvas).toBeVisible();
    const box = await canvas.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeGreaterThan(250);
    expect(box!.height).toBeGreaterThan(150);

    await page.getByLabel("Min severity filter").selectOption("high");
    await page.getByRole("button", { name: "Reset", exact: true }).click();

    await page.getByRole("button", { name: /Customer Orders Database/i }).click();
    await expect(page.getByText("filtered to target: db-01")).toBeVisible();
    await expect(page.getByText("R-EXP-REMOTE").first()).toBeVisible();
    await maybeCapture(page, "attack-paths.png");
  });

  test("3. Scenario Lab what-if comparison, custom builder, hash verification, and run diff", async () => {
    await page.getByRole("button", { name: "Scenario Lab", exact: true }).click();
    await expect(page.getByText("Defensive Action Comparison")).toBeVisible();
    await expect(page.getByText("Headline:")).toBeVisible();

    // Toggle D2 mitigation (remove RR-04 -> 22 -> 5)
    await page.getByLabel(/D2 · Remove zone flow RR-04/i).check();
    await expect(page.getByText("Before / After Path Comparison (Within Active Run)")).toBeVisible();
    await expect(page.getByText("removed").first()).toBeVisible();
    await expect(page.getByText("-17").first()).toBeVisible();
    await maybeCapture(page, "scenario-lab.png");

    // Toggle Baseline vs Modified topology view
    await page.getByRole("button", { name: "Baseline", exact: true }).click();
    await expect(page.getByText("Active Path · score 22/100")).toBeVisible();
    await page.getByRole("button", { name: "Modified", exact: true }).click();
    await expect(page.getByText("Active Path · score 5/100")).toBeVisible();

    // Build and execute custom assumed-breach scenario ad-hoc
    await page.getByRole("button", { name: /Build Scenario/i }).click();
    await page.getByLabel("Scenario Name").fill("E2E Workstation Pivot");
    await page.getByLabel("Builder Start Kind").selectOption("asset");
    await page.getByLabel("Builder Start Key").selectOption("ws-101");
    await page.getByRole("button", { name: /Run Ad-Hoc/i }).click();
    await expect(page.getByLabel("Scenario selector")).toHaveValue("__inline__");
    await expect(page.locator("td", { hasText: "E2E Workstation Pivot" }).first()).toBeVisible();

    // Verify reproducible hash and Run-to-Run comparison in Run History
    const verifyBtn = page.getByRole("button", { name: "Verify", exact: true }).first();
    await verifyBtn.click();
    await expect(page.getByText(/Verified reproducible hash/i)).toBeVisible();

    const setAButtons = page.getByRole("button", { name: "Set A", exact: true });
    const setBButtons = page.getByRole("button", { name: "Set B", exact: true });
    await setAButtons.first().click();
    await setBButtons.last().click();
    await expect(page.getByText(/Run-to-Run Comparison:/i)).toBeVisible();
  });

  test("4. Findings remediation workflow and immutable snapshot isolation", async () => {
    await page.getByRole("button", { name: "Findings", exact: true }).click();
    await expect(page.getByText("Findings Inventory")).toBeVisible();

    await page.getByLabel("Search findings").fill("F-005");
    await page.getByText("F-005").first().click();
    await expect(page.getByText("Status & Remediation Workflow")).toBeVisible();

    await page.getByLabel("Global Finding Status").selectOption("remediated");
    await page.getByLabel("Audit Transition Comment").fill("Patched in Playwright E2E");
    await page.getByRole("button", { name: "Save Workflow Changes" }).click();

    await expect(page.getByText(/Saved changes for F-005/i)).toBeVisible();
    await expect(page.getByText("open → remediated")).toBeVisible();
    await maybeCapture(page, "findings.png");

    // Freeze Snapshot #2 -> verify Attack Paths drops to 0 paths on the new snapshot
    const snapSelect = page.getByLabel("Snapshot selector");
    const countBefore = await snapSelect.locator("option").count();
    await page.getByRole("button", { name: /Freeze Snapshot/i }).click();
    await expect(snapSelect.locator("option")).toHaveCount(countBefore + 1);

    await page.getByRole("button", { name: "Attack Paths", exact: true }).click();
    await expect(page.getByText("0 modeled paths matched under current sweep parameters.")).toBeVisible();
  });

  test("5. Imports dry-run validation and HTML/Markdown report export downloads", async () => {
    await page.getByRole("button", { name: "Imports", exact: true }).click();
    await expect(page.getByText("Choose UTF-8 file (.json, .csv, .xml)")).toBeVisible();

    const payload = JSON.stringify({
      schema_version: 1,
      zones: [{ key: "dmz", name: "DMZ", trust_level: "low", intra_zone_policy: "deny" }],
    });
    await page.locator('input[type="file"]').setInputFiles({
      name: "e2e-validate.json",
      mimeType: "application/json",
      buffer: Buffer.from(payload, "utf-8"),
    });
    await page.getByRole("button", { name: /1\. Validate \(Dry-Run\)/i }).click();
    await expect(page.getByText("Status: validated")).toBeVisible();

    await page.getByRole("button", { name: "Reports", exact: true }).click();
    await expect(page.getByText("Scenario Reports & Audited Exports")).toBeVisible();
    await expect(page.locator("pre").getByText(/CHAOS LAB Scenario Report/i)).toBeVisible();

    const [htmlDownload] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Export Escaped HTML" }).click(),
    ]);
    expect(htmlDownload.suggestedFilename()).toMatch(/\.html$/);
    await expect(page.getByText(/Exported .*\.html/)).toBeVisible();

    const [mdDownload] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Export Markdown" }).click(),
    ]);
    expect(mdDownload.suggestedFilename()).toMatch(/\.md$/);
    await expect(page.getByText(/Exported .*\.md/)).toBeVisible();
  });

  test("6. Admin login, audit filters & chain verify, last-admin protection, and user create", async () => {
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByRole("button", { name: "Admin", exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Admin", exact: true }).click();
    await page.getByRole("button", { name: /Sign In to Operations Console/i }).click();

    await page.getByRole("button", { name: "Audit Trail", exact: true }).click();
    await page.getByPlaceholder("e.g. report.exported").fill("report.exported");
    await expect(page.locator("td", { hasText: "report.exported" }).first()).toBeVisible();
    await page.locator("tr", { hasText: "report.exported" }).first().click();
    await expect(page.locator("pre").getByText(/"format":/)).toBeVisible();

    await page.getByRole("button", { name: "Verify Hash Chain" }).click();
    await expect(page.getByText(/Audit hash chain verified intact/i)).toBeVisible();

    await page.getByRole("button", { name: "Admin", exact: true }).click();
    await expect(page.getByText("Last-admin protection active")).toBeVisible();

    // Sole active admin disable attempt must trigger 409 Conflict guard
    const adminRow = page.locator("tr", { hasText: "admin@meridian.example" });
    await adminRow.getByRole("button", { name: "Disable" }).click();
    await expect(
      page.getByText(/Cannot demote or disable the last active administrator/i)
    ).toBeVisible();

    // Create new viewer user cleanly
    await page.getByPlaceholder("operator@meridian.example").fill("e2e-viewer@meridian.example");
    await page.getByPlaceholder("SecOps Operator").fill("E2E Viewer");
    await page.getByPlaceholder("••••••••••••").fill("ViewerPass!2026");
    await page.getByLabel("New user role").selectOption("viewer");
    await page.getByRole("button", { name: "Create User" }).click();

    await expect(page.getByText(/Created viewer user e2e-viewer@meridian\.example/i)).toBeVisible();
    await expect(page.getByText("audit_chain_preserved=true")).toBeVisible();
    await maybeCapture(page, "admin.png");
  });
});
