import { NextResponse } from "next/server";

const DEFAULT_API_URL = "http://127.0.0.1:8000";

export async function GET(): Promise<NextResponse> {
  const apiUrl = process.env.API_URL ?? DEFAULT_API_URL;

  try {
    const response = await fetch(new URL("/health", apiUrl), {
      cache: "no-store",
      signal: AbortSignal.timeout(3_000),
    });

    if (!response.ok) {
      throw new Error(`API health check returned ${response.status}`);
    }

    return NextResponse.json(await response.json());
  } catch {
    return NextResponse.json(
      { service: "sentinel-api", status: "unavailable" },
      { status: 503 },
    );
  }
}
