import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AppShell } from "./app-shell";

describe("AppShell", () => {
  it("renders an accessible home control and working navigation controls", () => {
    const html = renderToStaticMarkup(<AppShell><div>Dashboard content</div></AppShell>);

    expect(html).toContain('aria-label="Return to Sentinel AI dashboard"');
    expect(html).toContain(">Overview</button>");
    expect(html).toContain(">Security Review</button>");
    expect(html).toContain(">Architecture</button>");
  });

  it("keeps the AI Security Code Review subtitle non-interactive", () => {
    const html = renderToStaticMarkup(<AppShell><div>Dashboard content</div></AppShell>);
    const subtitleIndex = html.indexOf("AI Security Code Review");

    expect(subtitleIndex).toBeGreaterThan(-1);
    expect(html).not.toContain("<a");
    expect(html.slice(subtitleIndex - 30, subtitleIndex + 80)).not.toContain("<button");
  });
});
