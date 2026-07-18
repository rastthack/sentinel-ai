import { NextResponse } from "next/server";

const DEFAULT_API_URL = "http://127.0.0.1:8000";

export async function POST(request: Request): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return safeErrorResponse(422);
  }
  if (!isGitHubScanRequest(body)) return safeErrorResponse(422);

  try {
    const apiUrl = process.env.API_URL ?? DEFAULT_API_URL;
    const response = await fetch(new URL("/api/scans/github", apiUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
      signal: AbortSignal.timeout(60_000),
    });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) return safeErrorResponse(response.status);
    return NextResponse.json(payload);
  } catch {
    return safeErrorResponse(500);
  }
}

function safeErrorResponse(status: number): NextResponse {
  const message = fallbackMessage(status);
  const code = fallbackCode(status);
  return NextResponse.json({ detail: { code, message } }, { status });
}

function isGitHubScanRequest(value: unknown): value is { github_url: string } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 1 && typeof record.github_url === "string";
}

function fallbackMessage(status: number): string {
  if (status === 422) return "Enter a valid public GitHub repository URL.";
  if (status === 413) return "This repository is too large to scan safely.";
  if (status === 502) return "The repository could not be accessed. Confirm that it is public and available.";
  if (status === 504) return "The repository took too long to download.";
  return "The repository could not be scanned.";
}

function fallbackCode(status: number): string {
  if (status === 422) return "github_url_invalid";
  if (status === 413) return "github_repository_too_large";
  if (status === 502) return "github_repository_unavailable";
  if (status === 504) return "github_clone_timed_out";
  return "github_scan_failed";
}
