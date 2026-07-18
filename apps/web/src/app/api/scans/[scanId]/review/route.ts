import { NextResponse } from "next/server";

const DEFAULT_API_URL = "http://127.0.0.1:8000";
const SCAN_ID = /^[A-Za-z0-9-]{1,128}$/;

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ scanId: string }> },
): Promise<NextResponse> {
  const { scanId } = await params;
  if (!SCAN_ID.test(scanId)) return unavailableResponse(404);

  try {
    const apiUrl = process.env.API_URL ?? DEFAULT_API_URL;
    const response = await fetch(new URL(`/api/scans/${scanId}/review`, apiUrl), {
      method: "POST",
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) return unavailableResponse(response.status);
    return NextResponse.json(payload);
  } catch {
    return unavailableResponse(502);
  }
}

function unavailableResponse(status: number): NextResponse {
  return NextResponse.json(
    {
      detail: {
        code: "reviewer_unavailable",
        message: "The optional reviewer is currently unavailable.",
      },
    },
    { status },
  );
}
