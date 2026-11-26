// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildFallbackExportFileName,
  MAX_FILE_STEM_LENGTH,
  parseContentDispositionFileName,
  sanitizeExportFileName,
  toDomainFileStem,
  toSafeFileStem,
} from "@/lib/cert-manager/certificate-export-file-name";

describe("parseContentDispositionFileName", () => {
  it.each([
    [
      'attachment; filename="example.com-fullchain.pem"',
      "example.com-fullchain.pem",
    ],
    ["attachment; filename=example.com-cert.pem", "example.com-cert.pem"],
    [
      "attachment; filename=\"fallback.pem\"; filename*=UTF-8''_wildcard.example.com.pfx",
      "_wildcard.example.com.pfx",
    ],
    ["attachment; filename*=utf-8''my%20cert.pem", "my_cert.pem"],
    ["attachment; filename*=UTF-8''bad%E0%A4%A.pem", "bad_e0_a4_a.pem"],
  ])("reads %s", (header, expected) => {
    expect(parseContentDispositionFileName(header)).toBe(expected);
  });

  it.each([
    [undefined],
    [""],
    ["attachment"],
    ['attachment; filename=""'],
    ['attachment; filename="..."'],
    [42],
  ])("returns null for %p", (header) => {
    expect(parseContentDispositionFileName(header)).toBeNull();
  });

  it("never lets a header choose a directory", () => {
    expect(
      parseContentDispositionFileName(
        'attachment; filename="../../etc/Passwd.pem"',
      ),
    ).toBe("passwd.pem");
    expect(
      parseContentDispositionFileName('attachment; filename="..\\\\key.pem"'),
    ).toBe("key.pem");
  });
});

describe("sanitizeExportFileName", () => {
  it("caps the length", () => {
    expect(sanitizeExportFileName(`${"a".repeat(300)}.pem`)).toHaveLength(128);
  });

  it("keeps only the last path segment and no leading dots", () => {
    expect(sanitizeExportFileName("dir/../.hidden.pem")).toBe("hidden.pem");
    expect(sanitizeExportFileName("C:\\keys\\-key.pem")).toBe("key.pem");
  });
});

// Mirrors the server's CertExportFileNamesTest, so the name saved when
// Content-Disposition is unreadable is the one the backend would have sent.
describe("toSafeFileStem (backend CertExportFileNames.safeCommonName)", () => {
  it.each([
    ["*.example.com", "_wildcard.example.com"],
    ["*.Example.com", "_wildcard.example.com"],
    ["example.com", "example.com"],
    ["  Shop.Example.COM  ", "shop.example.com"],
    ["a..b...com", "a.b.com"],
    ["-.-example.com.-", "example.com"],
    ["café.example.com", "caf-.example.com"],
    ["😀.example.com", "example.com"],
    ["shop😀.example.com", "shop--.example.com"],
  ])("turns %p into %p", (name, expected) => {
    expect(toSafeFileStem(name)).toBe(expected);
  });

  it("lets only safe characters survive", () => {
    const stem = toSafeFileStem('Ex"ample;\r\nX-Bad: 1/../é.COM');
    expect(stem).toMatch(/^[a-z0-9._-]+$/);
    expect(stem.startsWith("ex-ample")).toBe(true);
    expect(stem.endsWith(".com")).toBe(true);
    expect(stem).not.toContain("..");

    const traversal = toSafeFileStem("../../etc/passwd");
    expect(traversal).not.toContain("..");
    expect(traversal.startsWith(".")).toBe(false);
  });

  it.each([[null], [undefined], ["  "], ["..."], ["-.-"]])(
    "falls back to certificate for %p",
    (name) => {
      expect(toSafeFileStem(name)).toBe("certificate");
    },
  );

  it("bounds long names and trims a separator left by the cut", () => {
    expect(toSafeFileStem(`${"a".repeat(300)}.com`)).toHaveLength(
      MAX_FILE_STEM_LENGTH,
    );
    const cutAtDot = toSafeFileStem(`${"a".repeat(99)}.example.com`);
    expect(cutAtDot).toBe("a".repeat(99));
  });
});

describe("toDomainFileStem (backend stemFor without a leaf CN)", () => {
  it.each([
    ["example.com", true, "_wildcard.example.com"],
    ["example.com", false, "example.com"],
    ["*.example.com", true, "_wildcard.example.com"],
    ["", true, "certificate"],
    [undefined, false, "certificate"],
  ])("names %p (wildcard: %p) %p", (domain, isWildcard, expected) => {
    expect(toDomainFileStem(domain, isWildcard)).toBe(expected);
  });
});

describe("buildFallbackExportFileName", () => {
  it.each([
    ["FULLCHAIN_PEM", "example.com-fullchain.pem"],
    ["CERTIFICATE_PEM", "example.com-cert.pem"],
    ["PRIVATE_KEY_PEM", "example.com-privkey.pem"],
    ["PKCS12", "example.com.pfx"],
    ["CERTIFICATE_DER", "example.com-cert.der"],
    ["PKCS7", "example.com-chain.p7b"],
  ] as const)("names a %s fallback", (format, expected) => {
    expect(
      buildFallbackExportFileName(
        { domain: "example.com", isWildcard: false },
        format,
      ),
    ).toBe(expected);
  });

  it("names a wildcard certificate like the backend", () => {
    const wildcard = { domain: "example.com", isWildcard: true };
    expect(buildFallbackExportFileName(wildcard, "PKCS12")).toBe(
      "_wildcard.example.com.pfx",
    );
    expect(buildFallbackExportFileName(wildcard, "FULLCHAIN_PEM")).toBe(
      "_wildcard.example.com-fullchain.pem",
    );
  });

  it("uses a generic name without a source", () => {
    expect(buildFallbackExportFileName(undefined, "PKCS12")).toBe(
      "certificate.pfx",
    );
  });
});
