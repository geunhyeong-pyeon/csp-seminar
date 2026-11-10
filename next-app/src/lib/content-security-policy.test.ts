import { describe, expect, it } from "vitest";

import { buildContentSecurityPolicy, resolveCspHeaderName } from "./content-security-policy";

const directive = (policy: string, name: string) =>
  policy
    .split("; ")
    .find((part) => part.startsWith(`${name} `))
    ?.split(" ")
    .slice(1) ?? [];

describe("buildContentSecurityPolicy", () => {
  const production = buildContentSecurityPolicy({ nonce: "abc123", isDevelopment: false });

  it("allows scripts only through this request's nonce", () => {
    const scriptSources = directive(production, "script-src");
    expect(scriptSources).toContain("'nonce-abc123'");
    expect(scriptSources).toContain("'strict-dynamic'");
    expect(scriptSources).not.toContain("'unsafe-inline'");
  });

  it("never allows eval in production", () => {
    expect(directive(production, "script-src")).not.toContain("'unsafe-eval'");
  });

  it("allows eval in development only", () => {
    const development = buildContentSecurityPolicy({ nonce: "abc123", isDevelopment: true });
    expect(directive(development, "script-src")).toContain("'unsafe-eval'");
  });

  it("closes the non-script holes", () => {
    expect(directive(production, "object-src")).toEqual(["'none'"]);
    expect(directive(production, "base-uri")).toEqual(["'self'"]);
    expect(directive(production, "form-action")).toEqual(["'self'"]);
    expect(directive(production, "connect-src")).toEqual(["'self'"]);
  });

  it.each(["", "   "])("rejects an empty nonce (%j)", (nonce) => {
    expect(() => buildContentSecurityPolicy({ nonce, isDevelopment: false })).toThrow();
  });
});

describe("resolveCspHeaderName", () => {
  it.each([
    ["enforce", "Content-Security-Policy"],
    ["report-only", "Content-Security-Policy-Report-Only"],
    ["off", null],
  ] as const)("%s → %s", (mode, expected) => {
    expect(resolveCspHeaderName(mode)).toBe(expected);
  });
});
