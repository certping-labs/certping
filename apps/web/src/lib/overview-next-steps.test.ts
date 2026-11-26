// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { buildNextSteps } from "@/lib/overview-next-steps";

const quiet = {
  certificatesExpiring: 0,
  certificatesFailed: 0,
  deploymentsFailed: 0,
  priorityAlerts: 0,
};

describe("buildNextSteps first-run path", () => {
  it("walks a new organization admin through discovery, PQC, rotation, deployments and members", () => {
    const steps = buildNextSteps({
      ...quiet,
      totalCertificates: 0,
      canIssueCertificates: true,
    });

    expect(steps.map((s) => s.id)).toEqual([
      "onboarding:discover",
      "onboarding:pqc",
      "onboarding:rotation",
      "onboarding:deployments",
      "onboarding:members",
    ]);
    expect(steps.map((s) => s.action?.href)).toEqual([
      "/cert-manager/discovery",
      "/cert-manager/cryptography",
      "/cert-manager/rotation",
      "/integrations/deployment-targets",
      "/settings/organization-access?tab=members",
    ]);
    const text = steps.map((s) => `${s.title} ${s.detail}`).join(" ");
    for (const banned of ["feature flag", "demo"]) {
      expect(text.toLowerCase()).not.toContain(banned.toLowerCase());
    }
  });

  it("offers a viewer only the read-only steps", () => {
    const steps = buildNextSteps({
      ...quiet,
      totalCertificates: 0,
      canIssueCertificates: false,
    });
    expect(steps.map((s) => s.id)).toEqual([
      "onboarding:discover",
      "onboarding:pqc",
    ]);
  });

  it("drops a step whose feature is off", () => {
    const steps = buildNextSteps({
      ...quiet,
      totalCertificates: 0,
      canIssueCertificates: true,
      isRouteAvailable: (href) => href !== "/cert-manager/cryptography",
    });
    expect(steps.map((s) => s.id)).not.toContain("onboarding:pqc");
  });

  it("describes discovery as reading certificate stores, not scanning networks", () => {
    const steps = buildNextSteps({
      ...quiet,
      totalCertificates: 0,
      canIssueCertificates: true,
    });
    const copy = steps.map((s) => `${s.title} ${s.detail}`).join(" ");
    expect(copy).not.toMatch(/scan your networks/i);
    expect(copy).not.toMatch(/network|endpoint/i);
    const discover = steps.find((s) => s.id === "onboarding:discover");
    expect(discover?.detail).toMatch(
      /AWS Certificate Manager, Azure Key Vault and Kubernetes/,
    );
  });

  it("shows no first-run steps once certificates exist", () => {
    const steps = buildNextSteps({
      ...quiet,
      totalCertificates: 12,
      canIssueCertificates: true,
    });
    expect(steps.filter((s) => s.id.startsWith("onboarding:"))).toHaveLength(0);
  });
});
