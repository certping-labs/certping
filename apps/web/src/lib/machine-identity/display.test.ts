// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  asEnumValue,
  humanizeConstant,
  humanizeKey,
  pluralize,
} from "@/lib/machine-identity/display";

describe("humanizeConstant", () => {
  it("humanizes enum-style values", () => {
    expect(humanizeConstant("IDENTIFIER_UNVERIFIED")).toBe(
      "Identifier unverified",
    );
    expect(humanizeConstant("  REGISTERED  ")).toBe("Registered");
  });

  it.each([null, undefined, "", "   "])(
    "returns the default fallback for an absent value",
    (value) => {
      expect(humanizeConstant(value)).toBe("Unknown");
    },
  );

  it("supports a context-specific fallback", () => {
    expect(humanizeConstant(null, "Recorded")).toBe("Recorded");
  });
});

describe("humanizeKey", () => {
  it("splits camelCase and snake_case provider attribute keys", () => {
    expect(humanizeKey("scepServerHosts")).toBe("SCEP server hosts");
    expect(humanizeKey("azure_ad_device_id")).toBe("Azure AD device ID");
  });

  it("leaves an already-readable key alone", () => {
    expect(humanizeKey("model")).toBe("Model");
  });
});

describe("acronym handling", () => {
  // A PKI console that renders "Sign csr" and "Api host" reads as a typo, not
  // as sentence case.
  it.each([
    ["SIGN_CSR", "Sign CSR"],
    ["CA_ISSUANCE_STARTED", "CA issuance started"],
    ["MANAGED_ENDPOINT", "Managed endpoint"],
  ])("renders the constant %s as %s", (input, expected) => {
    expect(humanizeConstant(input)).toBe(expected);
  });

  it.each([
    ["apiHost", "API host"],
    ["mdmLastSyncAt", "MDM last sync at"],
    ["osVersion", "OS version"],
  ])("renders the key %s as %s", (input, expected) => {
    expect(humanizeKey(input)).toBe(expected);
  });
});

describe("pluralize", () => {
  it("does not render a count of one as a plural", () => {
    expect(pluralize(1, "day")).toBe("1 day");
    expect(pluralize(0, "day")).toBe("0 days");
    expect(pluralize(2, "day")).toBe("2 days");
  });

  it("accepts an irregular plural", () => {
    expect(pluralize(2, "entry", "entries")).toBe("2 entries");
  });
});

describe("asEnumValue", () => {
  const STATUSES = { REGISTERED: "", ORPHANED: "", DECOMMISSIONED: "" };

  it("keeps a value the API defines", () => {
    expect(asEnumValue("ORPHANED", STATUSES)).toBe("ORPHANED");
  });

  it.each([undefined, null, "", "BOGUS", "orphaned"])(
    "drops %p rather than letting the API reject it with a 400",
    (value) => {
      expect(asEnumValue(value, STATUSES)).toBeUndefined();
    },
  );

  it("ignores inherited object properties", () => {
    expect(asEnumValue("toString", STATUSES)).toBeUndefined();
  });
});
