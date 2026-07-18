import {
  isScanResponse,
  type RepositoryScanResponse,
  type ScanResponse,
} from "./scan-types";

export class DemoScanError extends Error {
  constructor() { super("The bundled demo scan is currently unavailable. Retry when the Sentinel API is ready."); }
}

export class GitHubScanError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function loadDemoScan(fetcher: typeof fetch = fetch): Promise<ScanResponse> {
  try {
    const response = await fetcher("/api/scans/demo", { cache: "no-store" });
    if (!response.ok) throw new DemoScanError();
    const payload: unknown = await response.json();
    if (!isScanResponse(payload)) throw new DemoScanError();
    return payload;
  } catch (error) {
    if (error instanceof DemoScanError) throw error;
    throw new DemoScanError();
  }
}

export async function scanGitHubRepository(
  githubUrl: string,
  fetcher: typeof fetch = fetch,
): Promise<RepositoryScanResponse> {
  try {
    const response = await fetcher("/api/scans/github", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ github_url: githubUrl }),
      cache: "no-store",
    });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      throw new GitHubScanError(response.status, apiErrorMessage(payload));
    }
    if (!isScanResponse(payload)) {
      throw new GitHubScanError(500, "The repository could not be scanned.");
    }
    return payload;
  } catch (error) {
    if (error instanceof GitHubScanError) throw error;
    throw new GitHubScanError(500, "The repository could not be scanned.");
  }
}

function apiErrorMessage(payload: unknown): string {
  if (!payload || typeof payload !== "object") return "The repository could not be scanned.";
  const detail = (payload as { detail?: unknown }).detail;
  if (!detail || typeof detail !== "object") return "The repository could not be scanned.";
  const message = (detail as { message?: unknown }).message;
  return typeof message === "string" ? message : "The repository could not be scanned.";
}
