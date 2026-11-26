// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { buildSupportHref } from "./support-reference-link";

const parse = (href: string) => new URL(href);

describe("buildSupportHref", () => {
  it("includes correlationId, domain and message when present", () => {
    const url = parse(
      buildSupportHref({
        correlationId: "corr-123",
        summary: "Certificate error",
        message: "Something failed",
        domain: "example.com",
      }),
    );

    expect(`${url.origin}${url.pathname}`).toBe(
      "https://github.com/certping-labs/certping/issues/new",
    );
    expect(url.searchParams.get("title")).toBe("Certificate error");
    expect(url.searchParams.get("body")).toBe(
      "Reference ID: corr-123\nDomain: example.com\nMessage: Something failed",
    );
  });

  it("omits the body when there are no details (legacy records)", () => {
    const url = parse(
      buildSupportHref({
        correlationId: null,
        summary: "Certificate deployment failed",
      }),
    );

    expect(url.searchParams.get("title")).toBe("Certificate deployment failed");
    expect(url.searchParams.has("body")).toBe(false);
  });
});
