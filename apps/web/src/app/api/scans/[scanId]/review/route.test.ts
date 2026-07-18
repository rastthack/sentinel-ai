import { afterEach, describe, expect, it, vi } from "vitest";

import { POST } from "./route";

describe("POST /api/scans/[scanId]/review", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.API_URL;
  });

  it("forwards only a validated scan ID to the review API", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: "complete" }), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);

    const response = await POST(new Request("http://test/api/scans/scan-123/review", { method: "POST" }), {
      params: Promise.resolve({ scanId: "scan-123" }),
    });

    expect(response.status).toBe(200);
    expect(fetcher).toHaveBeenCalledWith(new URL("http://127.0.0.1:8000/api/scans/scan-123/review"), expect.objectContaining({ method: "POST" }));
  });

  it("does not forward path-like IDs or backend diagnostics", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    const response = await POST(new Request("http://test/api/scans/invalid/review", { method: "POST" }), {
      params: Promise.resolve({ scanId: "../private" }),
    });

    expect(response.status).toBe(404);
    await expect(response.text()).resolves.not.toContain("private");
    expect(fetcher).not.toHaveBeenCalled();
  });
});
