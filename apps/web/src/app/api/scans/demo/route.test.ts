import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

describe("GET /api/scans/demo", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.API_URL;
  });

  it("returns the backend structure-discovery payload", async () => {
    const payload = { repository: { name: "vulnerable-taskflow" }, routes: [] };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(payload), {
          headers: { "content-type": "application/json" },
          status: 200,
        }),
      ),
    );

    const response = await GET();

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(payload);
  });

  it("does not expose backend errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("private detail")));

    const response = await GET();

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      detail: {
        code: "scan_unavailable",
        message: "The bundled demo scan is currently unavailable.",
      },
    });
  });
});
