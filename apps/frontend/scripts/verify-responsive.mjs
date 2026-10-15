import { mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const bundledModules = process.env.CODEX_BUNDLED_NODE_MODULES
  ?? path.join(os.homedir(), ".cache", "codex-runtimes", "codex-primary-runtime", "dependencies", "node", "node_modules");
const playwrightUrl = pathToFileURL(path.join(bundledModules, "playwright", "index.mjs")).href;
const { chromium } = await import(playwrightUrl);
const browserExecutable = process.env.CHROME_PATH
  ?? path.join(process.env.ProgramFiles ?? "C:\\Program Files", "Google", "Chrome", "Application", "chrome.exe");
const outputDirectory = path.join(os.tmpdir(), "astra-phase6-responsive");
await mkdir(outputDirectory, { recursive: true });

const viewports = [
  { width: 1440, height: 900 },
  { width: 1280, height: 800 },
  { width: 390, height: 844 },
];

const browser = await chromium.launch({ headless: true, executablePath: browserExecutable });
try {
  const results = [];
  for (const viewport of viewports) {
    const page = await browser.newPage({ viewport: viewport });
    await page.goto("http://localhost:5173/", { waitUntil: "networkidle" });
    await page.getByRole("tab", { name: /报告中心/ }).click();
    await page.getByRole("tab", { name: "受控评审" }).click();
    const metrics = await page.evaluate(() => ({
      width: innerWidth,
      height: innerHeight,
      document_width: document.documentElement.scrollWidth,
      horizontal_scroll: document.documentElement.scrollWidth > innerWidth,
      selected_workspace_tabs: document.querySelectorAll('.workspace-tab[aria-selected="true"]').length,
      selected_report_tabs: document.querySelectorAll('.report-tabs [aria-selected="true"]').length,
      context_fields: document.querySelectorAll(".project-context-bar input").length,
      review_workbench_visible: Boolean(document.querySelector("#review-workbench-title")),
      unnamed_buttons: [...document.querySelectorAll("button")].filter((button) => !(button.textContent || "").trim() && !button.getAttribute("aria-label")).length,
    }));
    const screenshotPath = path.join(outputDirectory, `${viewport.width}x${viewport.height}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: false });
    results.push({ ...metrics, screenshot: screenshotPath });
    await page.close();
  }
  const failures = results.flatMap((result) => [
    result.horizontal_scroll ? `${result.width}x${result.height}: horizontal scroll` : undefined,
    result.selected_workspace_tabs !== 1 ? `${result.width}x${result.height}: workspace selected=${result.selected_workspace_tabs}` : undefined,
    result.selected_report_tabs !== 1 ? `${result.width}x${result.height}: report selected=${result.selected_report_tabs}` : undefined,
    result.context_fields !== 5 ? `${result.width}x${result.height}: context fields=${result.context_fields}` : undefined,
    !result.review_workbench_visible ? `${result.width}x${result.height}: review workbench hidden` : undefined,
    result.unnamed_buttons !== 0 ? `${result.width}x${result.height}: unnamed buttons=${result.unnamed_buttons}` : undefined,
  ].filter(Boolean));
  console.log(JSON.stringify({ ok: failures.length === 0, results, failures }, null, 2));
  if (failures.length > 0) process.exitCode = 1;
} finally {
  await browser.close();
}
