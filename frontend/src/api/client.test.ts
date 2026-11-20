import { describe, expect, it, vi, beforeEach } from "vitest";
import { api, ApiError, apiFetch } from "./client";

describe("apiFetch", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("attaches X-Requested-With: chaoslab and credentials on POST mutations", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const data = await apiFetch<{ ok: boolean }>("/snapshots/snap-1/runs", {
      method: "POST",
      body: JSON.stringify({ scenario_id: "sc-1" }),
    });

    expect(data.ok).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/snapshots/snap-1/runs");
    expect(init.credentials).toBe("include");
    const headers = init.headers as Headers;
    expect(headers.get("X-Requested-With")).toBe("chaoslab");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("omits X-Requested-With on GET and includes credentials", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), { status: 200 })
    );
    vi.stubGlobal("fetch", mockFetch);

    await apiFetch("/environments");
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe("include");
    const headers = init.headers as Headers;
    expect(headers.has("X-Requested-With")).toBe(false);
  });

  it("throws ApiError with detail from JSON error responses", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "Permission scenarios:run is required." }), {
        status: 403,
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    await expect(apiFetch("/snapshots/1/runs", { method: "POST" })).rejects.toMatchObject({
      name: "ApiError",
      status: 403,
      detail: "Permission scenarios:run is required.",
    } satisfies Partial<ApiError>);
  });

  it("preserves multipart boundary by omitting JSON Content-Type for FormData uploads", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "validated" }), { status: 200 })
    );
    vi.stubGlobal("fetch", mockFetch);

    const form = new FormData();
    form.append("format", "json");
    form.append("file", new Blob(["{}"], { type: "application/json" }), "bundle.json");

    await apiFetch("/environments/env-1/imports/validate", { method: "POST", body: form });
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get("X-Requested-With")).toBe("chaoslab");
    expect(headers.has("Content-Type")).toBe(false);
    expect(init.credentials).toBe("include");
  });

  it("sends CSRF header and body on createScenario, deleteScenario, and inline runScenario", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: "sc-new", name: "Custom" }), { status: 201 })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: "run-inline" }), { status: 201 })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ result_kind: "run_comparison" }), { status: 200 })
      );
    vi.stubGlobal("fetch", mockFetch);

    await api.createScenario("env-1", {
      name: "Custom Pivot",
      description: "Test custom",
      start_kind: "asset",
      start_key: "ws-101",
      start_level: "user",
      targets: [{ asset_key: "dc-01", level: "admin" }],
      max_depth: 6,
      k_paths: 5,
      max_expansions: 5000,
    });
    const [createUrl, createInit] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(createUrl).toBe("/api/environments/env-1/scenarios");
    expect(createInit.method).toBe("POST");
    expect((createInit.headers as Headers).get("X-Requested-With")).toBe("chaoslab");

    await api.deleteScenario("env-1", "sc-new");
    const [delUrl, delInit] = mockFetch.mock.calls[1] as [string, RequestInit];
    expect(delUrl).toBe("/api/environments/env-1/scenarios/sc-new");
    expect(delInit.method).toBe("DELETE");
    expect((delInit.headers as Headers).get("X-Requested-With")).toBe("chaoslab");

    await api.runScenario("snap-1", {
      inline_scenario: {
        name: "Ad-hoc",
        start_kind: "zone",
        start_key: "internet",
        start_level: "user",
        targets: [{ asset_key: "db-01", level: "user" }],
        max_depth: 6,
        k_paths: 5,
        max_expansions: 1000,
      },
      actions: [],
    });
    const [, runInit] = mockFetch.mock.calls[2] as [string, RequestInit];
    const parsedRunBody = JSON.parse(String(runInit.body)) as Record<string, unknown>;
    expect(parsedRunBody).toHaveProperty("inline_scenario");
    expect(parsedRunBody).not.toHaveProperty("scenario_id");

    await api.compareRuns("run-1", "run-2");
    const [cmpUrl, cmpInit] = mockFetch.mock.calls[3] as [string, RequestInit];
    expect(cmpUrl).toBe("/api/runs/compare?run_a_id=run-1&run_b_id=run-2");
    expect(cmpInit.method).toBe("GET");
    expect((cmpInit.headers as Headers).has("X-Requested-With")).toBe(false);
  });

  it("supports report export, audit query filters, and admin user mutations", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response("<h1>Report</h1>", {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Disposition": 'attachment; filename="chaoslab-orders-run-1.html"',
            "X-Report-SHA256": "deadbeef1234",
          },
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ total: 0, items: [] }), { status: 200 })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: "u-2", role: "analyst" }), { status: 201 })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: "u-2", is_active: false }), { status: 200 })
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ user_id: "u-2", email: "sec@meridian.example", sessions_revoked: 1 }),
          { status: 200 }
        )
      );
    vi.stubGlobal("fetch", mockFetch);

    const exported = await api.exportRunReport("run-1", "html");
    expect(exported.filename).toBe("chaoslab-orders-run-1.html");
    expect(exported.reportSha256).toBe("deadbeef1234");
    const [expUrl, expInit] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(expUrl).toBe("/api/runs/run-1/report/export");
    expect(expInit.method).toBe("POST");
    expect((expInit.headers as Record<string, string>)["X-Requested-With"]).toBe("chaoslab");

    await api.listAudit({
      action: "report.exported",
      actor: "analyst",
      subject_type: "scenario_run",
      limit: 25,
      offset: 50,
    });
    const [audUrl] = mockFetch.mock.calls[1] as [string, RequestInit];
    expect(audUrl).toContain("/api/audit?");
    expect(audUrl).toContain("action=report.exported");
    expect(audUrl).toContain("actor=analyst");
    expect(audUrl).toContain("offset=50");

    await api.createUser({
      email: "sec@meridian.example",
      display_name: "Sec User",
      password: "StrongPassword!2026",
      role: "analyst",
    });
    const [uCreateUrl, uCreateInit] = mockFetch.mock.calls[2] as [string, RequestInit];
    expect(uCreateUrl).toBe("/api/admin/users");
    expect(uCreateInit.method).toBe("POST");
    expect((uCreateInit.headers as Headers).get("X-Requested-With")).toBe("chaoslab");

    await api.updateUser("u-2", { is_active: false });
    const [uPatchUrl, uPatchInit] = mockFetch.mock.calls[3] as [string, RequestInit];
    expect(uPatchUrl).toBe("/api/admin/users/u-2");
    expect(uPatchInit.method).toBe("PATCH");

    await api.resetUserPassword("u-2", "RotatedPassword!2026");
    const [uResetUrl, uResetInit] = mockFetch.mock.calls[4] as [string, RequestInit];
    expect(uResetUrl).toBe("/api/admin/users/u-2/reset-password");
    expect(uResetInit.method).toBe("POST");
  });
});
