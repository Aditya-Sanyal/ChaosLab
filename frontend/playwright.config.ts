import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: {
    timeout: 12_000,
  },
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:5174",
    viewport: { width: 1440, height: 900 },
    acceptDownloads: true,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
  webServer: [
    {
      command: "node e2e/start-backend.mjs",
      url: "http://127.0.0.1:8011/api/health/ready",
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: "npx vite --host 127.0.0.1 --port 5174 --strictPort",
      url: "http://127.0.0.1:5174",
      reuseExistingServer: false,
      timeout: 30_000,
      env: {
        VITE_API_TARGET: "http://127.0.0.1:8011",
      },
    },
  ],
});
