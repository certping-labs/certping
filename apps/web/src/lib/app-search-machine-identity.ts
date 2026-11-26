// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  DEVICE_CERTIFICATE_ALIASES,
  MACHINE_IDENTITY_ALIASES,
} from "@/lib/app-search-aliases";
import {
  type AppSearchContext,
  type AppSearchItem,
  createAppSearchItem,
} from "@/lib/app-search-types";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";
import { FEATURE_FLAGS } from "@/lib/feature-flags";

/**
 * Machine Identity entries for the command palette.
 *
 * <p>Gated exactly as the sidebar gates the same routes: an enterprise
 * deployment with an organization context, then the two independent backend
 * flags - devices, certificates and connectors come from
 * `IOT_DEVICE_MANAGEMENT`, profiles from the separate
 * `IOT_CERTIFICATE_PROFILE_MANAGEMENT`. Search must not offer a destination the
 * navigation hides, or it becomes a way to reach a page that answers 423.
 */
export function getMachineIdentitySearchItems({
  hasOrganization,
  isFeatureEnabled,
}: AppSearchContext): AppSearchItem[] {
  if (!isEnterpriseAppMode() || !hasOrganization) {
    return [];
  }

  const items: AppSearchItem[] = [];

  if (isFeatureEnabled(FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT)) {
    items.push(
      createAppSearchItem(
        "Devices",
        "Device inventory synced from your connected sources.",
        "/machine-identity/devices",
        "Machine Identity",
        [
          "device",
          "devices",
          "laptop",
          "endpoint",
          "inventory",
          "orphaned",
          "fleet",
          ...MACHINE_IDENTITY_ALIASES,
        ],
      ),
      createAppSearchItem(
        "Device Certificates",
        "Certificates issued to devices across every connected CA.",
        "/machine-identity/device-certificates",
        "Machine Identity",
        [
          "expiring",
          "expired",
          "issued",
          ...DEVICE_CERTIFICATE_ALIASES,
          ...MACHINE_IDENTITY_ALIASES,
        ],
      ),
      // Both live under Integrations now, one category each, but they stay
      // gated on IOT_DEVICE_MANAGEMENT and stay findable under the old
      // "connectors" wording that the UI itself no longer uses.
      createAppSearchItem(
        "Certificate authorities",
        "CAs your agents advertise, and whether each is accepting issuance.",
        "/integrations/certificate-authorities",
        "Integrations",
        [
          "connector",
          "connectors",
          "ca",
          "certificate authority",
          "ca health",
          "ejbca",
          "smallstep",
          ...DEVICE_CERTIFICATE_ALIASES,
          ...MACHINE_IDENTITY_ALIASES,
        ],
      ),
      createAppSearchItem(
        "Device sources",
        "Inventories your agents sync devices from, and how each sync is running.",
        "/integrations/device-sources",
        "Integrations",
        [
          "connector",
          "connectors",
          "device source",
          "sources",
          "sync",
          "agent health",
          "intune",
          "jamf",
          ...DEVICE_CERTIFICATE_ALIASES,
          ...MACHINE_IDENTITY_ALIASES,
        ],
      ),
    );
  }

  if (isFeatureEnabled(FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT)) {
    items.push(
      createAppSearchItem(
        "Certificate Profiles",
        "What CertPing delivers to a device source, such as an Intune SCEP profile.",
        "/machine-identity/profiles",
        "Machine Identity",
        [
          "profile",
          "profiles",
          "certificate profile",
          "scep profile",
          "template",
          ...DEVICE_CERTIFICATE_ALIASES,
          ...MACHINE_IDENTITY_ALIASES,
        ],
      ),
      createAppSearchItem(
        "New Certificate Profile",
        "Create a certificate profile for a device source.",
        "/machine-identity/profiles/new",
        "Machine Identity",
        [
          "add profile",
          "new profile",
          "create profile",
          "new certificate profile",
          ...MACHINE_IDENTITY_ALIASES,
        ],
      ),
    );
  }

  return items;
}
