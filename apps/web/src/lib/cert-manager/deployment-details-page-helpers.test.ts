// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  formatDeploymentStatusLabel,
  getCredentialPresentation,
  getDeploymentStatusBadgeVariant,
  getSnapshotHealthLabel,
  getTriggeredBy,
  getTriggeredByBadgeVariant,
} from "@/lib/cert-manager/deployment-details-page-helpers";
import type {
  CredentialReference,
  DeploymentRecord,
} from "@/types/cert-manager";

function makeDeployment(
  overrides: Partial<DeploymentRecord>,
): DeploymentRecord {
  return {
    requestId: "req-1",
    status: "SUCCESS",
    domain: "example.com",
    createdAt: "2026-01-01T00:00:00.000Z",
    metadata: {},
    ...overrides,
  } as DeploymentRecord;
}

describe("deployment-details-page-helpers", () => {
  it("formats status labels into Title Case", () => {
    expect(formatDeploymentStatusLabel("FAILED_DEPLOYMENT")).toBe(
      "Failed Deployment",
    );
  });

  it("maps status to badge variants", () => {
    expect(getDeploymentStatusBadgeVariant("SUCCESS")).toBe("success");
    expect(getDeploymentStatusBadgeVariant("FAILED_VALIDATION")).toBe(
      "destructive",
    );
    expect(getDeploymentStatusBadgeVariant("DEPLOYING")).toBe("warning");
    expect(getDeploymentStatusBadgeVariant("UNKNOWN")).toBe("secondary");
  });

  it("extracts triggeredBy metadata safely", () => {
    expect(
      getTriggeredBy(makeDeployment({ metadata: { triggeredBy: "AUTO" } })),
    ).toBe("AUTO");
    expect(
      getTriggeredBy(
        makeDeployment({ metadata: { triggeredBy: 123 as unknown as string } }),
      ),
    ).toBe("-");
  });

  it("maps triggeredBy values to badge variants", () => {
    expect(getTriggeredByBadgeVariant("AUTO")).toBe("info");
    expect(getTriggeredByBadgeVariant("MANUAL")).toBe("warning");
    expect(getTriggeredByBadgeVariant("unknown")).toBe("secondary");
  });

  it("computes snapshot health label with error override", () => {
    expect(
      getSnapshotHealthLabel(
        makeDeployment({ userMessage: "Something needs attention" }),
      ),
    ).toBe("Needs attention");
    expect(getSnapshotHealthLabel(makeDeployment({ status: "SUCCESS" }))).toBe(
      "Healthy snapshot",
    );
    expect(
      getSnapshotHealthLabel(makeDeployment({ status: "DEPLOYING" })),
    ).toBe("In flight");
    expect(getSnapshotHealthLabel(makeDeployment({ status: "CAPTURED" }))).toBe(
      "Captured",
    );
  });

  it("computes credential presentation fallbacks", () => {
    const deployment = makeDeployment({
      deploymentCredentialXref: "cred-xref",
    });
    const presentation = getCredentialPresentation(undefined, deployment);
    expect(presentation.title).toBe("cred-xref");
    expect(presentation.subtitle).toBe("cred-xref");

    const credential: CredentialReference = {
      credentialXref: "cred-1",
      description: "vault path",
      provider: "AWS",
      targetType: "CLOUDFLARE",
    } as CredentialReference;
    const credentialPresentation = getCredentialPresentation(
      credential,
      deployment,
    );
    expect(credentialPresentation.title).toBe("vault path");
    expect(credentialPresentation.subtitle).toBe("CLOUDFLARE");
  });
});
