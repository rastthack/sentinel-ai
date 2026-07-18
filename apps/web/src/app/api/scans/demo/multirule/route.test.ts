import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

describe("GET /api/scans/demo/multirule", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.API_URL;
  });

  it("forwards the controlled multi-rule request to the dedicated backend endpoint", async () => {
    const payload = { repository: { name: "vulnerable-multirule" }, findings: [] };
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);

    const response = await GET();

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(payload);
    expect(fetcher).toHaveBeenCalledWith(new URL("http://127.0.0.1:8000/api/scans/demo/multirule"), expect.objectContaining({ cache: "no-store" }));
  });

  it("does not expose backend diagnostics", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("private detail")));

    const response = await GET();

    expect(response.status).toBe(503);
    await expect(response.text()).resolves.not.toContain("private detail");
  });
});
