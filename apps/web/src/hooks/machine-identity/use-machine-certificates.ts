// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  getCertificate,
  getCertificateHistory,
  listCertificates,
  listDeviceCertificates,
  requestCertificateDeviceSync,
  revokeCertificate,
} from "@/lib/backend/machine-identity/certificates";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  adaptiveRefetchInterval,
  ambientRefetchInterval,
  liveRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { getErrorMessage } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth-store";
import type {
  CertificateDetail,
  CertificateListParams,
  CreateIotRevocationRequest,
  DeviceSyncResponse,
  DeviceSyncSelection,
  DeviceSyncSkipReason,
} from "@/types/machine-identity-backend";
import { machineIdentityKeys } from "./query-keys";
import { useIsDeviceManagementOn } from "@/hooks/machine-identity/use-machine-identity-access";

interface QueryOptions {
  enabled?: boolean;
}

export function useCertificates(
  params: CertificateListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.certificateList(user?.organizationId, params),
    queryFn: () => listCertificates(params),
    enabled: isFeatureOn && options.enabled !== false,
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    // Device certificates are issued by the CA when a device runs SCEP - no
    // action in this app precedes them, so an inventory left open would
    // otherwise never show the certificate that just landed.
    refetchInterval: liveRefetchInterval,
  });
}

/**
 * A certificate whose correlation, enrollment, revocation, or renewal nudge is
 * still settling is worth watching closely; one that finished months ago is
 * not. Certificates are stored the moment the CA issues them, so the device
 * and profile links can arrive later, on a subsequent sync.
 *
 * <p>Revocation and the nudge are both fire-and-report: the operator gets a
 * `202` here and the real outcome lands minutes later when the agent reports
 * back, with nothing in this app to trigger a refetch when it does.
 */
function isCertificateSettling(
  certificate: CertificateDetail | undefined,
): boolean {
  if (!certificate) return false;
  if (certificate.enrollment && !certificate.enrollment.completedAt) {
    return true;
  }
  if (
    certificate.status === "REVOCATION_PENDING" ||
    certificate.status === "REVOCATION_DISPATCHED"
  ) {
    return true;
  }
  if (certificate.renewalState === "NUDGING") {
    return true;
  }
  return certificate.device === null || certificate.profile === null;
}

export function useCertificate(
  certificateXref: string | undefined,
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.certificate(
      user?.organizationId,
      certificateXref,
    ),
    queryFn: () => getCertificate(certificateXref as string),
    enabled:
      isFeatureOn && options.enabled !== false && Boolean(certificateXref),
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.detail.staleTimeMs,
    refetchInterval: (query) =>
      adaptiveRefetchInterval(
        query,
        isCertificateSettling,
        MACHINE_IDENTITY_CONFIG.polling.ambientMs,
      ),
  });
}

export function useCertificateHistory(
  certificateXref: string | undefined,
  params: { page?: number; size?: number } = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.certificateHistory(
      user?.organizationId,
      certificateXref,
      params,
    ),
    queryFn: () => getCertificateHistory(certificateXref as string, params),
    enabled:
      isFeatureOn && options.enabled !== false && Boolean(certificateXref),
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    // Enrollment writes several events within a minute or two, then stops.
    refetchInterval: ambientRefetchInterval,
  });
}

/** Manual Intune check-in request with an immediate queued/skipped summary. */
function checkInToast(response: DeviceSyncResponse): string {
  if (response.queuedDevices === 1 && response.skippedDevices === 0) {
    return "Device check-in queued";
  }
  if (response.queuedDevices > 0) {
    return `${response.queuedDevices} device check-ins queued${
      response.skippedDevices > 0 ? `; ${response.skippedDevices} skipped` : ""
    }`;
  }
  const reason = response.devices.find(
    (device) => device.status === "SKIPPED",
  )?.reason;
  if (response.skippedDevices === 1 && reason) {
    return `No check-in queued. ${checkInSkipReason(reason)}`;
  }
  return response.skippedDevices === 1
    ? "Device was not eligible for check-in"
    : `${response.skippedDevices} devices were not eligible for check-in`;
}

/** Plain-language phrasing for the backend's device-sync skip reasons. */
function checkInSkipReason(reason: DeviceSyncSkipReason): string {
  switch (reason) {
    case "DEVICE_NOT_FOUND":
      return "The device is no longer in the registry.";
    case "UNSUPPORTED_OR_INACTIVE_SOURCE":
      return "Its source is inactive, or does not support check-ins.";
    case "NO_MANAGED_DEVICE_ID":
      return "The source never reported a managed device id for it.";
    case "NO_CURRENT_CERTIFICATE":
      return "It holds no current certificate to renew.";
    case "OUTSIDE_RENEWAL_THRESHOLD":
      return "Its certificate has not reached the profile's renewal window yet.";
    case "PROFILE_THRESHOLD_UNAVAILABLE":
      return "Its profile declares no renewal window, so CertPing cannot judge eligibility.";
    case "COOLDOWN_ACTIVE":
      return "A check-in went out recently and is still in cooldown.";
  }
}

export function useRequestCertificateDeviceSync() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (selection: DeviceSyncSelection) =>
      requestCertificateDeviceSync(selection),
    onSuccess: async (response) => {
      const message = checkInToast(response);
      if (response.queuedDevices > 0) {
        toast.success(message);
      } else {
        toast.warning(message);
      }
      // The org-scoped `certificates` key is a prefix over the detail, history,
      // and list queries. Device detail pages keep their certificate list under
      // the devices prefix, so refresh both views of the same records.
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: machineIdentityKeys.certificates(user?.organizationId),
        }),
        queryClient.invalidateQueries({
          queryKey: machineIdentityKeys.devices(user?.organizationId),
        }),
      ]);
    },
    onError: (error) => {
      toast.error(
        getErrorMessage(error, "The device check-in could not be requested"),
      );
    },
  });
}

export function useDeviceCertificates(
  deviceXref: string | undefined,
  params: { page?: number; size?: number } = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.deviceCertificateList(
      user?.organizationId,
      deviceXref,
      params,
    ),
    queryFn: () => listDeviceCertificates(deviceXref as string, params),
    enabled: isFeatureOn && options.enabled !== false && Boolean(deviceXref),
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: liveRefetchInterval,
  });
}

/**
 * How many certificates match `params`, taken from the server's own
 * `totalElements`.
 *
 * <p>Asks for a single row rather than a page of results. The KPI tiles used
 * to bucket one `maxPageSize` page client-side, which quietly undercounted
 * every organization holding more certificates than that and downloaded 200
 * rows that were never rendered.
 */
export function useCertificateCount(
  params: CertificateListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const countParams: CertificateListParams = { ...params, page: 0, size: 1 };
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.certificateList(
      user?.organizationId,
      countParams,
    ),
    queryFn: () => listCertificates(countParams),
    select: (page) => page.totalElements,
    enabled: isFeatureOn && options.enabled !== false,
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    // A tile that is a minute or two behind the table costs nothing; four
    // tiles polling as fast as the table costs four times the requests.
    refetchInterval: ambientRefetchInterval,
  });
}

/**
 * Requests revocation of one certificate.
 *
 * <p>The caller owns the idempotency key rather than the hook minting one:
 * a retry has to send the key it used the first time, and a hook that
 * generated a key per call would turn one timed-out request into two
 * revocation operations. See `@/lib/machine-identity/idempotency`.
 *
 * <p>Invalidates the whole certificate namespace on success - the row's status
 * changes to `REVOCATION_PENDING`, so the list and every count tile are stale
 * too, not just the detail page.
 */
export function useRevokeCertificate() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: ({
      certificateXref,
      input,
      idempotencyKey,
    }: {
      certificateXref: string;
      input: CreateIotRevocationRequest;
      idempotencyKey: string;
    }) => revokeCertificate(certificateXref, input, idempotencyKey),
    onSuccess: async () => {
      toast.success(
        "Revocation requested. The agent will submit it to the CA shortly.",
      );
      // Both namespaces: the inventory list lives under `certificates`, but a
      // device's own certificates tab is cached under `devices`, and it shows
      // the same row.
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: machineIdentityKeys.certificates(user?.organizationId),
        }),
        queryClient.invalidateQueries({
          queryKey: machineIdentityKeys.devices(user?.organizationId),
        }),
      ]);
    },
    onError: (error) => {
      toast.error(
        getErrorMessage(error, "The certificate could not be revoked"),
      );
    },
  });
}
