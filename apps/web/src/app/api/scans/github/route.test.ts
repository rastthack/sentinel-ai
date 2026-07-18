import { afterEach, describe, expect, it, vi } from "vitest";

import { POST } from "./route";

describe("POST /api/scans/github", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.API_URL;
  });

  it("forwards the GitHub URL to the backend endpoint", async () => {
    const payload = { repository: { name: "repository" }, findings: [] };
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);

    const response = await POST(new Request("http://test/api/scans/github", {
      method: "POST",
      body: JSON.stringify({ github_url: "https://github.com/owner/repository" }),
      headers: { "content-type": "application/json" },
    }));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(payload);
    expect(fetcher).toHaveBeenCalledWith(new URL("http://127.0.0.1:8000/api/scans/github"), expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ github_url: "https://github.com/owner/repository" }),
    }));
  });

  it("returns safe fallback errors instead of backend diagnostics or HTML", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>private stderr</html>", { status: 502 })));

    const response = await POST(new Request("http://test/api/scans/github", {
      method: "POST",
      body: JSON.stringify({ github_url: "https://github.com/owner/repository" }),
    }));

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      detail: {
        code: "github_repository_unavailable",
        message: "The repository could not be accessed. Confirm that it is public and available.",
      },
    });
  });

  it("rejects unexpected bodies without forwarding a local path upstream", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    const localPath = "/private/example/repository";

    const response = await POST(new Request("http://test/api/scans/github", {
      method: "POST",
      body: JSON.stringify({ repository_path: localPath }),
    }));

    expect(response.status).toBe(422);
    await expect(response.text()).resolves.not.toContain(localPath);
    expect(fetcher).not.toHaveBeenCalled();
  });
});
