import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { ScanProgress } from "./scan-progress";

describe("ScanProgress", () => {
  it("renders only truthful stage-based loading messages for demo scans", () => {
    const html = renderToStaticMarkup(<ScanProgress onCancel={vi.fn()} source="demo" />);

    for (const stage of ["Preparing repository", "Running deterministic security checks", "Building evidence package", "Generating security review"]) {
      expect(html).toContain(stage);
    }
    expect(html).toContain("TaskFlow AI demo");
    expect(html).not.toContain("%");
  });

  it("identifies GitHub scans without changing the workflow stages", () => {
    const html = renderToStaticMarkup(<ScanProgress onCancel={vi.fn()} source="github" />);

    expect(html).toContain("public GitHub repository");
    expect(html).toContain("Generating security review");
  });
});
