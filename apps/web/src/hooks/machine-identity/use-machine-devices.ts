// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

/**
 * Device inventory hooks (real IoT device backend, no mock fallback).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  archiveDevice,
  decommissionDevice,
  getDevice,
  listDeviceEvents,
  listDevices,
  restoreDevice,
} from "@/lib/backend/machine-identity/devices";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  ambientRefetchInterval,
  liveRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { getErrorMessage } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth-store";
import type {
  DeviceEventListParams,
  DeviceListParams,
} from "@/types/machine-identity-backend";
import { machineIdentityKeys } from "./query-keys";
import { useIsDeviceManagementOn } from "@/hooks/machine-identity/use-machine-identity-access";

interface QueryOptions {
  enabled?: boolean;
}

/** One zero-based page of the device inventory. */
export function useDevices(
  params: DeviceListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.deviceList(user?.organizationId, params),
    queryFn: () => listDevices(params),
    enabled: isFeatureOn && options.enabled !== false,
    // `placeholderData` keeps the previous page on screen while the next one
    // loads, so paging does not blank the table out from under the operator.
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    // Devices arrive on the hourly source sync, which nobody in this app
    // triggers. `useDeviceSources` invalidates this list the moment a run it
    // is watching finishes; this cadence covers the runs no open page saw.
    refetchInterval: liveRefetchInterval,
  });
}

/**
 * How many devices match `params`, from the server's own `totalElements`.
 *
 * <p>The KPI tiles cannot read `GET /iot/summary` for this: the summary is
 * always fleet-wide, so as soon as a source, OS, or compliance filter is
 * applied it describes a different population than the table underneath it -
 * the exact "tile says 7, table shows 3" mismatch the tiles exist to avoid.
 * Asking for one row keeps each tile the same query as the view it applies.
 */
export function useDeviceCount(
  params: DeviceListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const countParams: DeviceListParams = { ...params, page: 0, size: 1 };
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.deviceList(user?.organizationId, countParams),
    queryFn: () => listDevices(countParams),
    select: (page) => page.totalElements,
    enabled: isFeatureOn && options.enabled !== false,
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: ambientRefetchInterval,
  });
}

export function useDevice(
  deviceXref: string | undefined,
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.device(user?.organizationId, deviceXref),
    queryFn: () => getDevice(deviceXref as string),
    enabled: isFeatureOn && options.enabled !== false && Boolean(deviceXref),
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.detail.staleTimeMs,
    // Posture, compliance and last-seen all move on the source's own schedule.
    refetchInterval: liveRefetchInterval,
  });
}

export function useDeviceEvents(
  deviceXref: string | undefined,
  params: DeviceEventListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.deviceEventList(
      user?.organizationId,
      deviceXref,
      params,
    ),
    queryFn: () => listDeviceEvents(deviceXref as string, params),
    enabled: isFeatureOn && options.enabled !== false && Boolean(deviceXref),
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: ambientRefetchInterval,
  });
}

/**
 * Hides an orphaned device from the inventory.
 *
 * <p>Refetches the device rather than trusting a local edit: the backend refuses the request when
 * the device still holds a usable certificate, and its message names how many.
 */
export function useArchiveDevice() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (deviceXref: string) => archiveDevice(deviceXref),
    onSuccess: async (_result, deviceXref) => {
      toast.success("Device archived");
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.devices(user?.organizationId),
      });
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.device(user?.organizationId, deviceXref),
      });
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.summary(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "The device could not be archived"));
    },
  });
}

/** Puts an archived device back in the inventory. */
export function useRestoreDevice() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (deviceXref: string) => restoreDevice(deviceXref),
    onSuccess: async (_result, deviceXref) => {
      toast.success("Device restored to the inventory");
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.devices(user?.organizationId),
      });
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.device(user?.organizationId, deviceXref),
      });
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.summary(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "The device could not be restored"));
    },
  });
}

/** Marks a device decommissioned - a PKI-administrative state only. */
export function useDecommissionDevice() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (deviceXref: string) => decommissionDevice(deviceXref),
    onSuccess: async (device) => {
      toast.success(`${device.deviceName ?? "Device"} decommissioned`);
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.devices(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "The device could not be updated"));
    },
  });
}
