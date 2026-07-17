import { isScanResponse, type ScanResponse } from "./scan-types";

export class DemoScanError extends Error {
  constructor() { super("The bundled demo scan is currently unavailable. Retry when the Sentinel API is ready."); }
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
