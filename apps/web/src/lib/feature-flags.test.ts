// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  FEATURE_FLAGS,
  featureFlagLabel,
  type FeatureFlagKey,
} from "@/lib/feature-flags";

describe("FEATURE_FLAGS", () => {
  it("uses each key as its own value, so a typo cannot silently gate nothing", () => {
    for (const [name, value] of Object.entries(FEATURE_FLAGS)) {
      expect(value).toBe(name);
    }
  });

  it("carries the machine-identity flags the IoT endpoints gate on", () => {
    // These are the keys `/api/v1/iot/*` names in a 423 body.
    expect(FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT).toBe("IOT_DEVICE_MANAGEMENT");
    expect(FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT).toBe(
      "IOT_CERTIFICATE_PROFILE_MANAGEMENT",
    );
    expect(FEATURE_FLAGS.IOT_PROVIDER_INTUNE).toBe("IOT_PROVIDER_INTUNE");
    expect(FEATURE_FLAGS.CA_EJBCA).toBe("CA_EJBCA");
    expect(FEATURE_FLAGS.CA_SMALLSTEP).toBe("CA_SMALLSTEP");
  });
});

describe("featureFlagLabel", () => {
  it("uses the product name, not the constant", () => {
    expect(featureFlagLabel("IOT_DEVICE_MANAGEMENT")).toBe("Machine Identity");
    expect(featureFlagLabel("NOTIFICATION_PREFERENCES")).toBe(
      "Notification settings page",
    );
    expect(featureFlagLabel("LETS_ENCRYPT")).toBe("Let's Encrypt");
  });

  it("stays readable for a flag the backend added before this catalogue", () => {
    // A 423 naming an unknown key must still produce a sentence, not a
    // SCREAMING_CONSTANT in the middle of a paragraph.
    expect(featureFlagLabel("SOME_BRAND_NEW_FLAG")).toBe("Some brand new flag");
  });

  it("falls back to a generic subject when the body names no flag", () => {
    expect(featureFlagLabel(undefined)).toBe("This feature");
  });

  it("labels every key it claims to know", () => {
    for (const key of Object.values(FEATURE_FLAGS) as FeatureFlagKey[]) {
      expect(featureFlagLabel(key).length).toBeGreaterThan(0);
      expect(featureFlagLabel(key)).not.toContain("_");
    }
  });
});
