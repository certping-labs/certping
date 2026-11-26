// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Device source adapter (real backend, no mock fallback).
 *
 * <p>Sources are agent-advertised: an agent's configured Intune (or other)
 * connection appears here automatically once it reports its first health
 * message. There is no create/configure endpoint and no single-source GET -
 * a source's own detail must be found by filtering the list.
 */
import { apiClient, apiRoutes } from "@/lib/api";
import type {
  DeviceSourceDto,
  DeviceSourceEventListParams,
  DeviceSourceEventPage,
  SourceSyncAcceptedResponse,
} from "@/types/machine-identity-backend";
import {
  compactParams,
  resolvePageRequest,
  type ResolvedPageRequest,
} from "./transport";

export interface ResolvedDeviceSourceEventParams extends ResolvedPageRequest {
  correlationId?: string;
}

export function resolveDeviceSourceEventParams(
  params: DeviceSourceEventListParams = {},
): ResolvedDeviceSourceEventParams {
  return {
    ...resolvePageRequest(params),
    ...compactParams({ correlationId: params.correlationId }),
  };
}

/** All device sources advertised for the org, newest-created first. */
export async function listDeviceSources(): Promise<DeviceSourceDto[]> {
  const response = await apiClient.get<DeviceSourceDto[]>(
    apiRoutes.query.iotDevices.sources,
  );
  return response.data;
}

export async function listDeviceSourceEvents(
  sourceXref: string,
  params: DeviceSourceEventListParams = {},
): Promise<DeviceSourceEventPage> {
  const resolved = resolveDeviceSourceEventParams(params);
  const response = await apiClient.get<DeviceSourceEventPage>(
    apiRoutes.query.iotDevices.sourceEvents(sourceXref),
    { params: resolved },
  );
  return response.data;
}

/**
 * Requests a full device sync. The response is `202 Accepted`: the sync runs
 * asynchronously, so callers must poll `listDeviceSources` and watch for the
 * returned `syncXref` to reach a terminal `sync.status`.
 */
export async function triggerDeviceSourceSync(
  sourceXref: string,
): Promise<SourceSyncAcceptedResponse> {
  const response = await apiClient.post<SourceSyncAcceptedResponse>(
    apiRoutes.mutation.iotDevices.sourceSync(sourceXref),
  );
  return response.data;
}

/**
 * Stops future scheduled syncs for this source. This does NOT cancel a sync
 * already in flight - there is no cancel-in-flight endpoint.
 */
export async function stopDeviceSourceSync(
  sourceXref: string,
): Promise<DeviceSourceDto> {
  const response = await apiClient.post<DeviceSourceDto>(
    apiRoutes.mutation.iotDevices.sourceSyncStop(sourceXref),
  );
  return response.data;
}
