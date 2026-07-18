import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { ScanProgress } from "./scan-progress";

describe("ScanProgress", () => {
  it("renders only truthful stage-based loading messages for demo scans", () => {
    const html = renderToStaticMarkup(<ScanProgress onCancel={vi.fn()} source="taskflow" />);

    for (const stage of ["Preparing repository", "Running deterministic security checks", "Building evidence package", "Generating security review"]) {
      expect(html).toContain(stage);
    }
    expect(html).toContain("TaskFlow AI demo");
    expect(html).toContain("Run TaskFlow Demo Scan is running…");
    expect(html).not.toContain("%");
  });

  it("identifies GitHub scans without changing the workflow stages", () => {
    const html = renderToStaticMarkup(<ScanProgress onCancel={vi.fn()} source="github" />);

    expect(html).toContain("public GitHub repository");
    expect(html).toContain("Generating security review");
  });

  it("identifies the active multi-rule action without fabricating progress", () => {
    const html = renderToStaticMarkup(<ScanProgress onCancel={vi.fn()} source="multirule" />);

    expect(html).toContain("multi-rule demo");
    expect(html).toContain("Run Multi-Rule Demo Scan is running…");
    expect(html).not.toContain("%");
  });
});
