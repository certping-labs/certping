// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  PARTIAL_DISCOVERY_MESSAGE,
  discoveryConfigStatusFallbackMessage,
  discoveryConfigStatusLabel,
  discoveryConfigStatusMessage,
  discoveryConfigStatusVariant,
  discoveryFailedScopes,
  formatFailedScope,
  isActiveDiscoveryConfigStatus,
  isFailedDiscoveryConfigStatus,
  isTerminalDiscoveryConfigStatus,
} from "@/lib/cert-manager/discovery-status";

describe("isTerminalDiscoveryConfigStatus", () => {
  it("returns true for terminal statuses", () => {
    expect(isTerminalDiscoveryConfigStatus("COMPLETE")).toBe(true);
    expect(isTerminalDiscoveryConfigStatus("FAILED")).toBe(true);
    expect(isTerminalDiscoveryConfigStatus("CREDENTIAL_INVALID")).toBe(true);
  });

  it("returns false for in-flight statuses", () => {
    expect(isTerminalDiscoveryConfigStatus("READY")).toBe(false);
    expect(isTerminalDiscoveryConfigStatus("STARTED")).toBe(false);
    expect(isTerminalDiscoveryConfigStatus("IN_PROGRESS")).toBe(false);
    expect(isTerminalDiscoveryConfigStatus("CONFIG_REQUIRED")).toBe(false);
  });

  it("returns false for null or undefined", () => {
    expect(isTerminalDiscoveryConfigStatus(null)).toBe(false);
    expect(isTerminalDiscoveryConfigStatus(undefined)).toBe(false);
  });
});

describe("isActiveDiscoveryConfigStatus", () => {
  it("returns true only while a scan is in flight", () => {
    expect(isActiveDiscoveryConfigStatus("STARTED")).toBe(true);
    expect(isActiveDiscoveryConfigStatus("IN_PROGRESS")).toBe(true);
  });

  it("returns false for idle and terminal statuses", () => {
    expect(isActiveDiscoveryConfigStatus("READY")).toBe(false);
    expect(isActiveDiscoveryConfigStatus("COMPLETE")).toBe(false);
    expect(isActiveDiscoveryConfigStatus("FAILED")).toBe(false);
    expect(isActiveDiscoveryConfigStatus("CREDENTIAL_INVALID")).toBe(false);
    expect(isActiveDiscoveryConfigStatus(null)).toBe(false);
  });
});

describe("cancelled discovery runs", () => {
  it("treats CANCELLED as terminal so polling stops", () => {
    expect(isTerminalDiscoveryConfigStatus("CANCELLED")).toBe(true);
    expect(isActiveDiscoveryConfigStatus("CANCELLED")).toBe(false);
  });

  it("reads as a neutral word, not a failure", () => {
    expect(discoveryConfigStatusLabel("CANCELLED")).toBe("Cancelled");
    expect(discoveryConfigStatusVariant("CANCELLED")).toBe("secondary");
    expect(isFailedDiscoveryConfigStatus("CANCELLED")).toBe(false);
  });

  it("explains a cancelled run that carries no message", () => {
    expect(discoveryConfigStatusFallbackMessage("CANCELLED")).toMatch(
      /^This scan was cancelled\.$/,
    );
    expect(discoveryConfigStatusFallbackMessage("STARTED")).toMatch(
      /waiting for the next agent update/,
    );
  });
});

describe("partial discovery runs", () => {
  const base = {
    status: "PARTIAL" as const,
    message: "",
  };

  it("is terminal, a warning, and never a failure", () => {
    expect(isTerminalDiscoveryConfigStatus("PARTIAL")).toBe(true);
    expect(isActiveDiscoveryConfigStatus("PARTIAL")).toBe(false);
    expect(isFailedDiscoveryConfigStatus("PARTIAL")).toBe(false);
    expect(discoveryConfigStatusVariant("PARTIAL")).toBe("warning");
    expect(discoveryConfigStatusLabel("PARTIAL")).toBe("Partial");
  });

  it("says it is partial when the server sends no failed scopes", () => {
    expect(discoveryConfigStatusMessage(base)).toBe(PARTIAL_DISCOVERY_MESSAGE);
    expect(
      discoveryConfigStatusMessage({ ...base, failedScopes: null }),
    ).toMatch(/^Partial: some accounts or namespaces failed/);
    expect(
      discoveryConfigStatusMessage({ ...base, message: "2 of 5 accounts" }),
    ).toBe(`${PARTIAL_DISCOVERY_MESSAGE} 2 of 5 accounts`);
  });

  it("lists the failed scopes when the server returns them", () => {
    const message = discoveryConfigStatusMessage({
      ...base,
      failedScopes: [
        {
          scopeType: "AWS_ACCOUNT",
          scopeId: "222222222222",
          errorCode: "DISCOVERY_AWS_ACCOUNT_ACCESS_DENIED",
          message: "AccessDenied",
        },
        {
          scopeType: "K8S_NAMESPACE",
          scopeId: "payments",
          errorCode: null,
        },
      ],
    });
    expect(message).toMatch(/^Partial: some accounts or namespaces failed: /);
    expect(message).toContain(
      "AWS account 222222222222 (DISCOVERY_AWS_ACCOUNT_ACCESS_DENIED)",
    );
    expect(message).toContain("Namespace payments");
  });

  it("ignores malformed failed scopes", () => {
    expect(
      discoveryFailedScopes({
        failedScopes: [
          null as never,
          { scopeType: "AWS_REGION", scopeId: "111111111111/us-east-1" },
          { scopeType: "UNREADABLE", scopeId: null },
        ],
      }),
    ).toHaveLength(2);
    expect(formatFailedScope({ scopeType: "UNREADABLE", scopeId: null })).toBe(
      "Unreadable",
    );
    expect(formatFailedScope({ scopeType: null })).toBe("Unknown scope");
    expect(
      formatFailedScope({ scopeType: "AWS_REGION", scopeId: "1/us-east-1" }),
    ).toBe("AWS region 1/us-east-1");
  });

  it("leaves other statuses' messages as they were", () => {
    expect(
      discoveryConfigStatusMessage({ status: "FAILED", message: "denied" }),
    ).toBe("denied");
    expect(
      discoveryConfigStatusMessage({ status: "STARTED", message: "" }),
    ).toMatch(/waiting for the next agent update/);
  });
});

describe("discoveryConfigStatusVariant", () => {
  it("maps each status family to one tone", () => {
    expect(discoveryConfigStatusVariant("COMPLETE")).toBe("success");
    expect(discoveryConfigStatusVariant("FAILED")).toBe("destructive");
    expect(discoveryConfigStatusVariant("CREDENTIAL_INVALID")).toBe(
      "destructive",
    );
    expect(discoveryConfigStatusVariant("IN_PROGRESS")).toBe("warning");
    expect(discoveryConfigStatusVariant("READY")).toBe("secondary");
    expect(discoveryConfigStatusLabel("CREDENTIAL_INVALID")).toBe(
      "Credential invalid",
    );
  });
});
