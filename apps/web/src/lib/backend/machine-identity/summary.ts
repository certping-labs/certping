// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Fleet-wide device/source summary (real backend, no mock fallback).
 */
import { apiClient, apiRoutes } from "@/lib/api";
import type { IotSummary } from "@/types/machine-identity-backend";

export async function getIotSummary(): Promise<IotSummary> {
  const response = await apiClient.get<IotSummary>(
    apiRoutes.query.iotDevices.summary,
  );
  return response.data;
}
