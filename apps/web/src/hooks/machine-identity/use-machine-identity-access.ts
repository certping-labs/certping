// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useIsOrgFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";

/**
 * Devices, device certificates, CA connectors, device sources and the IoT
 * summary sit behind IOT_DEVICE_MANAGEMENT on the API (`@FeatureGated` on
 * IotDeviceController and IotCertificateController). Their queries wait until
 * the flag is confirmed on, so a disabled org never sees 423 noise.
 */
export function useIsDeviceManagementOn(): boolean {
  return useIsOrgFeatureEnabled(FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT);
}

/** Certificate profiles have their own gate (IotCertificateProfileController). */
export function useIsProfileManagementOn(): boolean {
  return useIsOrgFeatureEnabled(
    FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT,
  );
}
