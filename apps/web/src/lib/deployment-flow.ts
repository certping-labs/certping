// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

const DEPLOYMENT_FLOW_LABELS = {
  MANUAL: "Manual Issuance",
  AUTO_POST_RENEWAL: "Auto after renewal",
  AUTO_POST_ISSUANCE: "Auto after issuance",
} as const;

export type DeploymentFlowType = keyof typeof DEPLOYMENT_FLOW_LABELS;

export const DEPLOYMENT_FLOW_OPTIONS = Object.entries(
  DEPLOYMENT_FLOW_LABELS,
).map(([value, label]) => ({
  value,
  label,
}));

export function formatDeploymentFlowType(value?: string | null): string {
  if (!value) {
    return DEPLOYMENT_FLOW_LABELS.MANUAL;
  }

  return (
    DEPLOYMENT_FLOW_LABELS[
      value.toUpperCase() as keyof typeof DEPLOYMENT_FLOW_LABELS
    ] ||
    value
      .toLowerCase()
      .replace(/_/g, " ")
      .replace(/\b\w/g, (char) => char.toUpperCase())
  );
}
