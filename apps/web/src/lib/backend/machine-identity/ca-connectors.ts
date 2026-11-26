// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * CA connectors and their latest reported health (real backend, no mock fallback).
 */
import { apiClient, apiRoutes } from "@/lib/api";
import type { CaConnectorResponse } from "@/types/machine-identity-backend";

/** Every configured CA connector for the org, ordered by CA provider then connector id. */
export async function listCaConnectors(): Promise<CaConnectorResponse[]> {
  const response = await apiClient.get<CaConnectorResponse[]>(
    apiRoutes.query.iotDevices.caConnectors,
  );
  return response.data;
}

export async function getCaConnector(
  connectorId: string,
): Promise<CaConnectorResponse> {
  const response = await apiClient.get<CaConnectorResponse>(
    apiRoutes.query.iotDevices.caConnector(connectorId),
  );
  return response.data;
}
