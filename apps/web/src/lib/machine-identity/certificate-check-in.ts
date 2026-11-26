// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { INTUNE_DEVICE_CHECK_IN_PERMISSION } from "@/lib/machine-identity/backend-display";
import type {
  DeviceDetail,
  DeviceSourceDto,
} from "@/types/machine-identity-backend";

interface CertificateCheckInContext {
  canManage: boolean;
  linkedDeviceXref: string | undefined;
  device: DeviceDetail | undefined;
  deviceLoading: boolean;
  deviceFailed: boolean;
  source: DeviceSourceDto | undefined;
  sourceLoading: boolean;
  sourceFailed: boolean;
}

/**
 * Returns why an operator cannot request an Intune check-in, or `null` when
 * the action is safe to offer. The backend remains authoritative for renewal
 * threshold and cooldown eligibility after this connector-level gate passes.
 */
export function certificateCheckInUnavailableReason({
  canManage,
  linkedDeviceXref,
  device,
  deviceLoading,
  deviceFailed,
  source,
  sourceLoading,
  sourceFailed,
}: CertificateCheckInContext): string | null {
  if (!canManage) {
    return "You need the iot_device:manage permission to request a device check-in.";
  }
  if (!linkedDeviceXref) {
    return "This certificate must be linked to a device before a check-in can be requested.";
  }
  if (deviceLoading) {
    return "Checking the linked device and its source permissions.";
  }
  if (deviceFailed || !device) {
    return "The linked device could not be loaded.";
  }
  // The summary is populated for an archived device now, so without this the UI would offer a
  // check-in the backend silently skips: its device selection excludes archived rows.
  if (device.archived) {
    return "This device is archived. Restore it to the inventory before requesting a check-in.";
  }
  if (device.source.provider !== "INTUNE") {
    return "Manual certificate check-in is currently available only for Microsoft Intune devices.";
  }
  if (sourceLoading) {
    return "Checking the Intune source permissions.";
  }
  if (sourceFailed || !source) {
    return "The Intune source health report could not be loaded.";
  }
  const permission = source.health?.permissions.find(
    (candidate) => candidate.name === INTUNE_DEVICE_CHECK_IN_PERMISSION,
  );
  if (!permission?.granted) {
    return `Grant ${INTUNE_DEVICE_CHECK_IN_PERMISSION} and wait for the next agent health report.`;
  }
  return null;
}
