// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  DEPLOYMENT_FLOW_OPTIONS,
  formatDeploymentFlowType,
} from "@/lib/deployment-flow";

describe("deployment-flow", () => {
  describe("DEPLOYMENT_FLOW_OPTIONS", () => {
    it("exposes stable value-label pairs for all supported flows", () => {
      expect(DEPLOYMENT_FLOW_OPTIONS).toEqual([
        { value: "MANUAL", label: "Manual Issuance" },
        { value: "AUTO_POST_RENEWAL", label: "Auto after renewal" },
        { value: "AUTO_POST_ISSUANCE", label: "Auto after issuance" },
      ]);
    });
  });

  describe("formatDeploymentFlowType", () => {
    it("defaults to manual for nullish or empty input", () => {
      expect(formatDeploymentFlowType(undefined)).toBe("Manual Issuance");
      expect(formatDeploymentFlowType(null)).toBe("Manual Issuance");
      expect(formatDeploymentFlowType("")).toBe("Manual Issuance");
    });

    it("maps known values regardless of casing", () => {
      expect(formatDeploymentFlowType("MANUAL")).toBe("Manual Issuance");
      expect(formatDeploymentFlowType("auto_post_renewal")).toBe(
        "Auto after renewal",
      );
      expect(formatDeploymentFlowType("Auto_Post_Issuance")).toBe(
        "Auto after issuance",
      );
    });

    it("title-cases unknown values from underscore format", () => {
      expect(formatDeploymentFlowType("CUSTOM_DEPLOYMENT_FLOW")).toBe(
        "Custom Deployment Flow",
      );
    });
  });
});
