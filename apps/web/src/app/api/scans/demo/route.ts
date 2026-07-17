import { NextResponse } from "next/server";

const DEFAULT_API_URL = "http://127.0.0.1:8000";

export async function GET(): Promise<NextResponse> {
  const apiUrl = process.env.API_URL ?? DEFAULT_API_URL;

  try {
    const response = await fetch(new URL("/api/scans/demo", apiUrl), {
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      throw new Error(`Demo scan returned ${response.status}`);
    }

    return NextResponse.json(await response.json());
  } catch {
    return NextResponse.json(
      {
        detail: {
          code: "scan_unavailable",
          message: "The bundled demo scan is currently unavailable.",
        },
      },
      { status: 503 },
    );
  }
}
