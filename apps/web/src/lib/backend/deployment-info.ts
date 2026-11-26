// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import type { DeploymentInfo } from "@/types/deployment-info";

/**
 * Fetches deployment metadata from the backend.
 * Public endpoint-works pre-auth (no Bearer token required).
 */
export async function getDeploymentInfo(): Promise<DeploymentInfo> {
  const res = await apiClient.get<DeploymentInfo>(
    apiRoutes.query.deploymentInfo,
  );
  return res.data;
}
