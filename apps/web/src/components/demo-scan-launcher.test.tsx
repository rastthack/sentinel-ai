import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  DemoScanLauncher,
  createGitHubSubmissionGuard,
  githubErrorMessage,
  githubUrlValidationError,
} from "./demo-scan-launcher";
import { GitHubScanError } from "../lib/demo-scan-service";

describe("DemoScanLauncher", () => {
  it("renders the public GitHub repository form and preserves the demo action", () => {
    const html = renderToStaticMarkup(<DemoScanLauncher />);

    expect(html).toContain("Public GitHub repository");
    expect(html).toContain("Only public GitHub HTTPS repository URLs are supported.");
    expect(html).toContain("https://github.com/owner/repository");
    expect(html).toContain("Scan repository");
    expect(html).toContain("Run TaskFlow Demo Scan");
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

  it("prevents duplicate GitHub submissions until the active request finishes", () => {
    const guard = createGitHubSubmissionGuard();

    expect(guard.tryStart()).toBe(true);
    expect(guard.tryStart()).toBe(false);
    guard.finish();
    expect(guard.tryStart()).toBe(true);
  });
});
