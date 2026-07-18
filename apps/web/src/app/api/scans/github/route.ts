import { NextResponse } from "next/server";

const DEFAULT_API_URL = "http://127.0.0.1:8000";

export async function POST(request: Request): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return safeErrorResponse(422);
  }

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
    if (!response.ok) return safeErrorResponse(response.status, payload);
    return NextResponse.json(payload);
  } catch {
    return safeErrorResponse(500);
  }
}

function safeErrorResponse(status: number, payload?: unknown): NextResponse {
  const message = safeMessage(payload) ?? fallbackMessage(status);
  const code = safeCode(payload) ?? "github_scan_failed";
  return NextResponse.json({ detail: { code, message } }, { status });
}

function safeMessage(payload: unknown): string | null {
  const detail = safeDetail(payload);
  return typeof detail?.message === "string" ? detail.message : null;
}

function safeCode(payload: unknown): string | null {
  const detail = safeDetail(payload);
  return typeof detail?.code === "string" ? detail.code : null;
}

function safeDetail(payload: unknown): { code?: unknown; message?: unknown } | null {
  if (!payload || typeof payload !== "object") return null;
  const detail = (payload as { detail?: unknown }).detail;
  return detail && typeof detail === "object" ? (detail as { code?: unknown; message?: unknown }) : null;
}

function fallbackMessage(status: number): string {
  if (status === 422) return "Enter a valid public GitHub repository URL.";
  if (status === 413) return "This repository is too large to scan safely.";
  if (status === 502) return "The repository could not be accessed. Confirm that it is public and available.";
  if (status === 504) return "The repository took too long to download.";
  return "The repository could not be scanned.";
}
