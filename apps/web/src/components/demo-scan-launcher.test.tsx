import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  DemoScanLauncher,
  createGitHubSubmissionGuard,
  createReviewRequestGuard,
  githubErrorMessage,
  githubUrlValidationError,
  initialReviewerPanelState,
  scrollToSection,
  shouldApplyReviewerResult,
} from "./demo-scan-launcher";
import { GitHubScanError } from "../lib/demo-scan-service";

describe("DemoScanLauncher", () => {
  it("renders the public GitHub repository form and preserves the demo action", () => {
    const html = renderToStaticMarkup(<DemoScanLauncher />);

    expect(html).toContain("AI-Assisted Deterministic Security Review");
    expect(html).toContain("Scan a public GitHub repository using deterministic security rules, then receive bounded, category-aware AI guidance based only on verified evidence.");
    expect(html).toContain("Scan Public Repository");
    expect(html).toContain("Public GitHub repository URL");
    expect(html).toContain("Only public GitHub HTTPS repository URLs are supported.");
    expect(html).toContain("https://github.com/owner/repository");
    expect(html).toContain("Scan repository");
    expect(html).toContain("Run TaskFlow Demo");
    expect(html).toContain("Authorization-focused controlled demo");
    expect(html).toContain("A controlled BOLA and ownership-validation example. Fixture code is never executed.");
    expect(html).toContain("Run Multi-Rule Demo");
    expect(html).toContain("Multi-rule controlled demo");
    expect(html).toContain("Fixture code is never executed.");
    expect(html).toContain("Currently supported deterministic checks");
    expect(html).toContain("Coverage is intentionally bounded and is not a comprehensive security assessment.");
  });

  it("validates only an empty or clearly non-GitHub URL on the client", () => {
    expect(githubUrlValidationError("")).toBe("Enter a public GitHub repository URL.");
    expect(githubUrlValidationError("https://gitlab.com/owner/repository")).toBe("Enter a public GitHub repository URL.");
    expect(githubUrlValidationError("https://github.com/owner/repository")).toBeNull();
  });

  it("maps API statuses to safe user messages without rendering internal detail", () => {
    expect(githubErrorMessage(new GitHubScanError(422, "internal"))).toBe("Enter a valid public GitHub repository URL.");
    expect(githubErrorMessage(new GitHubScanError(413, "internal"))).toBe("This repository is too large to scan safely.");
    expect(githubErrorMessage(new GitHubScanError(502, "internal"))).toBe("The repository could not be accessed. Confirm that it is public and available.");
    expect(githubErrorMessage(new GitHubScanError(504, "internal"))).toBe("The repository took too long to download.");
    expect(githubErrorMessage(new GitHubScanError(500, "private filesystem detail"))).toBe("The repository could not be scanned.");
    expect(githubErrorMessage(new Error("private filesystem detail"))).toBe("The repository could not be scanned.");
  });

  it("prevents a second demo or GitHub action until the active scan finishes", () => {
    const guard = createGitHubSubmissionGuard();

    expect(guard.tryStart()).toBe(true);
    expect(guard.tryStart()).toBe(false);
    guard.finish();
    expect(guard.tryStart()).toBe(true);
  });

  it("resets review state for a new scan and rejects stale review responses", () => {
    expect(initialReviewerPanelState()).toEqual({ kind: "loading" });
    expect(shouldApplyReviewerResult("scan-new", "scan-new")).toBe(true);
    expect(shouldApplyReviewerResult("scan-new", "scan-old")).toBe(false);
  });

  it("prevents duplicate active review requests but allows a retry after completion", () => {
    const guard = createReviewRequestGuard();

    expect(guard.tryStart("scan-123")).toBe(true);
    expect(guard.tryStart("scan-123")).toBe(false);
    expect(guard.tryStart("scan-456")).toBe(true);
    guard.finish("scan-123");
    expect(guard.tryStart("scan-123")).toBe(true);
  });

  it("scrolls each navigation destination to its stable section", () => {
    const scrollIntoView = vi.fn();
    const getElementById = vi.fn(() => ({ scrollIntoView }));
    vi.stubGlobal("document", { getElementById });

    scrollToSection("overview");
    scrollToSection("scan-controls");
    scrollToSection("architecture");

    expect(getElementById).toHaveBeenNthCalledWith(1, "overview");
    expect(getElementById).toHaveBeenNthCalledWith(2, "scan-controls");
    expect(getElementById).toHaveBeenNthCalledWith(3, "architecture");
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
    vi.unstubAllGlobals();
  });
});
