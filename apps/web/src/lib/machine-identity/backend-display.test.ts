// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CA_PROVIDER_LOGOS,
  CERTIFICATE_STATUS_LABELS,
  PROFILE_CONTROL_MODE_LABELS,
  PROFILE_LIFECYCLE_LABELS,
  PROFILE_ORIGIN_LABELS,
  PROFILE_PROVIDER_SYNC_STATUS_LABELS,
  PROVIDER_LABELS,
  PROVIDER_LOGOS,
  VENDOR_MARK_HEIGHT,
  VENDOR_MARK_MAX_WIDTH,
  caConnectorStatusVariant,
  caProviderLabel,
  canRequestRevocation,
  certificateStatusLabel,
  certificateStatusVariant,
  complianceStateLabel,
  complianceStateVariant,
  deviceStatusVariant,
  extendedKeyUsageLabel,
  formatKeyStrength,
  formatRemainingLifetime,
  NUDGE_OUTCOME_DESCRIPTIONS,
  nudgeOutcomeLabel,
  nudgeOutcomeVariant,
  profileLifecycleVariant,
  profileProviderSyncStatusVariant,
  providerLabel,
  sanTypeLabel,
  scepEnrollmentPath,
  sourceHealthVariant,
  sourceSyncStatusVariant,
  vendorMarkSize,
} from "@/lib/machine-identity/backend-display";

describe("vendorMarkSize", () => {
  it("lays a square symbol out at the module height", () => {
    expect(vendorMarkSize({ src: "/a.svg", aspect: 1 })).toEqual({
      width: VENDOR_MARK_HEIGHT,
      height: VENDOR_MARK_HEIGHT,
    });
  });

  it("gives a wide wordmark the width its aspect ratio needs", () => {
    // Forcing a 355x136 wordmark into a square slot made it read as a dot.
    const wide = vendorMarkSize({ src: "/a.svg", aspect: 355 / 136 });

    expect(wide.height).toBe(VENDOR_MARK_HEIGHT);
    expect(wide.width).toBeGreaterThan(VENDOR_MARK_HEIGHT * 2);
    expect(wide.width).toBeLessThanOrEqual(VENDOR_MARK_MAX_WIDTH);
  });

  it("scales an extreme wordmark down by height rather than overflowing", () => {
    // A 940x204 wordmark at the full mark height would be ~74px wide.
    const extreme = vendorMarkSize({ src: "/a.svg", aspect: 940 / 204 });

    expect(extreme.width).toBe(VENDOR_MARK_MAX_WIDTH);
    expect(extreme.height).toBeLessThan(VENDOR_MARK_HEIGHT);
    expect(extreme.height).toBeGreaterThan(0);
  });

  it("preserves the asset's aspect ratio in every branch", () => {
    const logos = [
      ...Object.values(PROVIDER_LOGOS),
      ...Object.values(CA_PROVIDER_LOGOS),
    ].filter((logo) => logo !== undefined);

    expect(logos.length).toBeGreaterThan(0);
    for (const logo of logos) {
      const { width, height } = vendorMarkSize(logo);
      expect(width / height).toBeCloseTo(logo.aspect, 0);
    }
  });

  it("honours a caller-supplied height", () => {
    expect(vendorMarkSize({ src: "/a.svg", aspect: 1 }, 24)).toEqual({
      width: 24,
      height: 24,
    });
  });
});

describe("provider and CA labels", () => {
  it("uses the vendor's own casing for known names", () => {
    expect(providerLabel("INTUNE")).toBe("Microsoft Intune");
    expect(caProviderLabel("SMALLSTEP")).toBe("Smallstep");
    expect(caProviderLabel("EJBCA")).toBe("EJBCA");
  });

  it("humanizes a provider the frontend does not know about yet", () => {
    // Still readable, and still acronym-aware rather than "Some new mdm".
    expect(providerLabel("SOME_NEW_MDM")).toBe("Some new MDM");
    expect(caProviderLabel("SOME_NEW_CA")).toBe("Some new CA");
  });
});

describe("scepEnrollmentPath", () => {
  it("is a path, never a full URL", () => {
    // The agent that terminates SCEP runs in the customer's network and is
    // routinely reachable only on an internal hostname, so the host is the
    // operator's to supply - guessing one would hand them a dead endpoint.
    const path = scepEnrollmentPath("intune-primary");
    expect(path).toBe("/scep/v1/intune-primary");
    expect(path).not.toMatch(/^https?:/);
  });

  it("routes on the connection profile ref", () => {
    expect(scepEnrollmentPath("intune-secondary")).toBe(
      "/scep/v1/intune-secondary",
    );
  });

  it("escapes a ref that would otherwise break out of the path segment", () => {
    expect(scepEnrollmentPath("a/b?c=1")).toBe("/scep/v1/a%2Fb%3Fc%3D1");
  });
});

describe("deviceStatusVariant", () => {
  it("flags orphaned devices as a warning, not a neutral historical state", () => {
    expect(deviceStatusVariant("ORPHANED")).toBe("warning");
  });

  it("separates registered from decommissioned", () => {
    expect(deviceStatusVariant("REGISTERED")).toBe("success");
    expect(deviceStatusVariant("DECOMMISSIONED")).toBe("secondary");
  });

  it("does not colour a status it was never given", () => {
    expect(deviceStatusVariant(null)).toBe("outline");
  });
});

describe("compliance state", () => {
  it("distinguishes a non-compliant device from an unreported one", () => {
    expect(complianceStateVariant("NON_COMPLIANT")).toBe("destructive");
    expect(complianceStateLabel("NON_COMPLIANT")).toBe("Non-compliant");

    expect(complianceStateVariant(null)).toBe("secondary");
    expect(complianceStateLabel(null)).toBe("Not reported");
  });

  it("passes an unrecognized vendor state through readably", () => {
    expect(complianceStateLabel("CONFIG_MANAGER")).toBe("Config manager");
  });
});

describe("formatRemainingLifetime", () => {
  it.each([
    [-2, "Expired 2 days ago"],
    [-1, "Expired 1 day ago"],
    [0, "Expires today"],
    [1, "1 day left"],
    [45, "45 days left"],
  ])("describes %i remaining days as %s", (days, expected) => {
    expect(formatRemainingLifetime(days)).toBe(expected);
  });
});

describe("source health and sync variants", () => {
  it("separates healthy from everything that needs a look", () => {
    expect(sourceHealthVariant("HEALTHY")).toBe("success");
    expect(sourceHealthVariant("UNHEALTHY")).toBe("destructive");
  });

  it("treats a stale report the same as a degraded one", () => {
    // A source whose last health report aged out is not known-good; it is
    // known-unknown, which is a warning, not a pass.
    expect(sourceHealthVariant("STALE")).toBe("warning");
    expect(sourceHealthVariant("DEGRADED")).toBe("warning");
    expect(sourceHealthVariant("UNKNOWN")).toBe("secondary");
  });

  it("marks a partial sync as a warning rather than a success", () => {
    // PARTIAL means Graph throttled some pages: neither success nor failure,
    // and colouring it green would hide an incomplete inventory.
    expect(sourceSyncStatusVariant("OK")).toBe("success");
    expect(sourceSyncStatusVariant("PARTIAL")).toBe("warning");
    expect(sourceSyncStatusVariant("FAILED")).toBe("destructive");
    expect(sourceSyncStatusVariant("PENDING")).toBe("info");
    expect(sourceSyncStatusVariant("RUNNING")).toBe("info");
  });

  it("distinguishes a CA that is unconfigured from one that is broken", () => {
    expect(caConnectorStatusVariant("HEALTHY")).toBe("success");
    expect(caConnectorStatusVariant("DEGRADED")).toBe("warning");
    expect(caConnectorStatusVariant("UNCONFIGURED")).toBe("secondary");
    for (const status of ["UNREACHABLE", "UNAUTHORIZED", "ERROR"] as const) {
      expect(caConnectorStatusVariant(status)).toBe("destructive");
    }
    expect(caConnectorStatusVariant("UNKNOWN")).toBe("secondary");
  });
});

describe("profile and certificate vocabulary", () => {
  it("labels every lifecycle, control mode, origin and sync status", () => {
    // These maps back select options; a missing key renders a blank choice.
    expect(Object.keys(PROFILE_LIFECYCLE_LABELS)).toEqual([
      "DRAFT",
      "ACTIVE",
      "ARCHIVED",
    ]);
    expect(Object.keys(PROFILE_CONTROL_MODE_LABELS)).toEqual([
      "CMS_MANAGED",
      "OBSERVED_ONLY",
    ]);
    expect(Object.keys(PROFILE_ORIGIN_LABELS)).toEqual([
      "CMS_CREATED",
      "PROVIDER_DISCOVERED",
    ]);
    expect(Object.keys(PROFILE_PROVIDER_SYNC_STATUS_LABELS)).toEqual([
      "NEVER",
      "PENDING",
      "IN_SYNC",
      "FAILED",
      "DRIFTED",
      // The state a completed discovery sets when the provider no longer has
      // the profile, and the only one the archive endpoint accepts.
      "NOT_FOUND",
    ]);
    for (const label of Object.values(PROFILE_PROVIDER_SYNC_STATUS_LABELS)) {
      expect(label).not.toContain("_");
    }
  });

  it("flags drift as a warning and a failed push as an error", () => {
    // Drift means the provider holds something CertPing did not put there.
    expect(profileProviderSyncStatusVariant("IN_SYNC")).toBe("success");
    expect(profileProviderSyncStatusVariant("DRIFTED")).toBe("warning");
    expect(profileProviderSyncStatusVariant("FAILED")).toBe("destructive");
    expect(profileProviderSyncStatusVariant("PENDING")).toBe("info");
    expect(profileProviderSyncStatusVariant("NEVER")).toBe("secondary");
    // A profile the provider has lost is a live delivery gap, not a neutral
    // historical state - devices stop receiving it.
    expect(profileProviderSyncStatusVariant("NOT_FOUND")).toBe("destructive");
  });

  it("keeps a draft visually distinct from an active profile", () => {
    expect(profileLifecycleVariant("ACTIVE")).toBe("success");
    expect(profileLifecycleVariant("DRAFT")).toBe("outline");
    expect(profileLifecycleVariant("ARCHIVED")).toBe("secondary");
  });

  it("escalates certificate status by urgency", () => {
    expect(certificateStatusVariant("ISSUED")).toBe("success");
    expect(certificateStatusVariant("EXPIRING")).toBe("warning");
    expect(certificateStatusVariant("EXPIRED")).toBe("destructive");
    // The backend passes any non-issued lifecycle value straight through as
    // the display status, so every one of them needs a label - a missing key
    // rendered `undefined` in the badge.
    expect(Object.keys(CERTIFICATE_STATUS_LABELS)).toEqual([
      "ISSUED",
      "EXPIRING",
      "EXPIRED",
      "REVOCATION_PENDING",
      "REVOCATION_DISPATCHED",
      "REVOKED",
      "REVOCATION_FAILED",
      "REVOCATION_OUTCOME_UNKNOWN",
    ]);
  });

  it("treats an in-flight revocation as informational and an unconfirmed one as dangerous", () => {
    expect(certificateStatusVariant("REVOCATION_PENDING")).toBe("info");
    expect(certificateStatusVariant("REVOCATION_DISPATCHED")).toBe("info");
    expect(certificateStatusVariant("REVOKED")).toBe("secondary");
    expect(certificateStatusVariant("REVOCATION_FAILED")).toBe("destructive");
    // The CA never confirmed, so the certificate may still be live and trusted
    // while the record reads as revoked. That is the dangerous reading.
    expect(certificateStatusVariant("REVOCATION_OUTCOME_UNKNOWN")).toBe(
      "destructive",
    );
  });

  it("never renders an unknown certificate status as undefined", () => {
    expect(certificateStatusLabel("REVOKED")).toBe("Revoked");
    // A lifecycle value added to the backend before it is added here still has
    // to read as something.
    expect(certificateStatusLabel("SOME_FUTURE_STATE")).toBe(
      "Some future state",
    );
  });

  it("refuses revocation exactly where the backend would", () => {
    const base = {
      status: "ISSUED",
      caProvider: "EJBCA",
      certificateAuthority: false,
    } as const;
    expect(canRequestRevocation(base)).toBe(true);
    expect(canRequestRevocation({ ...base, caProvider: "smallstep" })).toBe(
      true,
    );
    // 422 at the backend: no revocation path is wired up for this CA.
    expect(canRequestRevocation({ ...base, caProvider: "DIGICERT" })).toBe(
      false,
    );
    // 422: CA certificates are out of scope for this endpoint.
    expect(canRequestRevocation({ ...base, certificateAuthority: true })).toBe(
      false,
    );
    // 409: already revoked, or a revocation is already in flight.
    expect(canRequestRevocation({ ...base, status: "REVOKED" })).toBe(false);
    expect(
      canRequestRevocation({ ...base, status: "REVOCATION_PENDING" }),
    ).toBe(false);
    expect(
      canRequestRevocation({ ...base, status: "REVOCATION_DISPATCHED" }),
    ).toBe(false);
    // Expired is still revocable: an expired certificate can be revoked to
    // record a compromise that was only discovered afterwards.
    expect(canRequestRevocation({ ...base, status: "EXPIRED" })).toBe(true);
  });

  it("keeps a nudge outcome honest about what Intune actually did", () => {
    // The pill has to fit a table cell; the sentence that keeps it honest -
    // accepted the request, not renewed - lives in the description map.
    expect(nudgeOutcomeLabel("NUDGE_SENT")).toBe("Sent to Intune");
    expect(NUDGE_OUTCOME_DESCRIPTIONS.NUDGE_SENT).toContain(
      "decide whether it actually renews",
    );
    expect(nudgeOutcomeVariant("NUDGE_SENT")).toBe("success");
    expect(nudgeOutcomeVariant("REQUESTED")).toBe("info");
    expect(nudgeOutcomeVariant("INTUNE_REJECTED")).toBe("destructive");
    expect(nudgeOutcomeVariant("PUBLISH_FAILED")).toBe("destructive");
    expect(nudgeOutcomeLabel("SOMETHING_NEW")).toBe("Something new");
  });

  it("names every provider the backend schema allows", () => {
    // A provider without a label would render as a raw enum in the filter.
    for (const label of Object.values(PROVIDER_LABELS)) {
      expect(label).not.toContain("_");
      expect(label.trim()).not.toBe("");
    }
  });
});

describe("certificate field formatting", () => {
  it("translates ASN.1 general-name tags into words", () => {
    expect(sanTypeLabel("dNSName")).toBe("DNS");
    expect(sanTypeLabel("rfc822Name")).toBe("Email");
    expect(sanTypeLabel("uniformResourceIdentifier")).toBe("URI");
    expect(sanTypeLabel("iPAddress")).toBe("IP address");
  });

  it("passes an unrecognized SAN tag through rather than blanking it", () => {
    expect(sanTypeLabel("someNewName")).toBe("someNewName");
  });

  it("names the standard extended key usages", () => {
    expect(extendedKeyUsageLabel("1.3.6.1.5.5.7.3.1")).toBe(
      "Server authentication",
    );
    expect(extendedKeyUsageLabel("1.3.6.1.5.5.7.3.2")).toBe(
      "Client authentication",
    );
    // An unknown OID is still the most useful thing to print.
    expect(extendedKeyUsageLabel("1.2.3.4")).toBe("1.2.3.4");
  });

  it("describes a key by size or by curve, whichever the algorithm uses", () => {
    expect(formatKeyStrength({ keyAlgorithm: "RSA", keySize: 2048 })).toBe(
      "RSA 2048",
    );
    expect(
      formatKeyStrength({
        keyAlgorithm: "EC",
        keySize: null,
        publicKeyCurve: "secp256r1",
      }),
    ).toBe("EC secp256r1");
  });

  it("falls back to the algorithm alone when neither is reported", () => {
    expect(formatKeyStrength({ keyAlgorithm: "Ed25519", keySize: null })).toBe(
      "Ed25519",
    );
  });
});
