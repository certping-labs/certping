// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Device inventory adapter (real backend, no mock fallback).
 */
import { apiClient, apiRoutes } from "@/lib/api";
import type {
  DeviceDetail,
  DeviceEventListParams,
  DeviceEventPage,
  DeviceListParams,
  DevicePage,
} from "@/types/machine-identity-backend";
import {
  compactParams,
  resolvePageRequest,
  type ResolvedPageRequest,
} from "./transport";

/** Normalized request, used both as the query key and as the wire params (`search` -> `q`). */
export interface ResolvedDeviceListParams extends ResolvedPageRequest {
  source?: string;
  status?: string;
  complianceState?: string;
  os?: string;
  q?: string;
}

export function resolveDeviceListParams(
  params: DeviceListParams = {},
): ResolvedDeviceListParams {
  return {
    ...resolvePageRequest({
      ...params,
      sort: params.sort ?? "lastSeenInSourceAt",
    }),
    ...compactParams({
      source: params.source,
      status: params.status,
      complianceState: params.complianceState,
      os: params.os,
      q: params.search?.trim(),
    }),
  };
}

export async function listDevices(
  params: DeviceListParams = {},
): Promise<DevicePage> {
  const resolved = resolveDeviceListParams(params);
  const response = await apiClient.get<DevicePage>(
    apiRoutes.query.iotDevices.devices,
    { params: resolved },
  );
  return response.data;
}

export async function getDevice(deviceXref: string): Promise<DeviceDetail> {
  const response = await apiClient.get<DeviceDetail>(
    apiRoutes.query.iotDevices.device(deviceXref),
  );
  return response.data;
}

/**
 * Marks a device decommissioned - a PKI-administrative state that is never
 * reflected back to the source provider (Intune, etc.).
 */
export async function decommissionDevice(
  deviceXref: string,
): Promise<DeviceDetail> {
  const response = await apiClient.post<DeviceDetail>(
    apiRoutes.mutation.iotDevices.deviceDecommission(deviceXref),
  );
  return response.data;
}

/**
 * Takes an orphaned device out of the inventory. Nothing is deleted - the row, its certificates
 * and its history stay, and a device its source reports again returns on the next sync.
 *
 * <p>Replies `204`, so there is no device to return: the caller refetches.
 */
export async function archiveDevice(deviceXref: string): Promise<void> {
  await apiClient.post(apiRoutes.mutation.iotDevices.deviceArchive(deviceXref));
}

/** Puts an archived device back in the inventory. */
export async function restoreDevice(deviceXref: string): Promise<void> {
  await apiClient.post(apiRoutes.mutation.iotDevices.deviceRestore(deviceXref));
}

export function resolveDeviceEventParams(
  params: DeviceEventListParams = {},
): ResolvedPageRequest {
  return resolvePageRequest(params);
}

export async function listDeviceEvents(
  deviceXref: string,
  params: DeviceEventListParams = {},
): Promise<DeviceEventPage> {
  const resolved = resolveDeviceEventParams(params);
  const response = await apiClient.get<DeviceEventPage>(
    apiRoutes.query.iotDevices.deviceEvents(deviceXref),
    { params: resolved },
  );
  return response.data;
}
