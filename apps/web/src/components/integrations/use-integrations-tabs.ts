// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMemo } from "react";

import { useCertificateAuthorities } from "@/hooks/ca-credentials";
import { useCredentials } from "@/hooks/credentials";
import { getCredentialTabCount } from "@/lib/cert-manager/credentials-page-helpers";
import { useListIntegrations } from "@/hooks/integrations";
import { useCaConnectors } from "@/hooks/machine-identity/use-ca-connectors";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";
import { useAuth } from "@/hooks/use-auth";
import { useFeatureFlags } from "@/hooks/use-feature-flags";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";
import {
  canViewCredentials,
  canViewIntegrations,
  hasOrganizationContext,
} from "@/lib/authz";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  INTEGRATIONS_APPS_HREF,
  INTEGRATIONS_CERTIFICATE_AUTHORITIES_HREF,
  INTEGRATIONS_DEPLOYMENT_TARGETS_HREF,
  INTEGRATIONS_DEVICE_SOURCES_HREF,
  INTEGRATIONS_DNS_HREF,
  type IntegrationsTabId,
} from "@/lib/integrations/routes";

export interface IntegrationsTab {
  id: IntegrationsTabId;
  href: string;
  label: string;
  /**
   * True for categories nobody can add to from the console - they self-register
   * when a deployed agent first checks in.
   */
  autoDiscovered: boolean;
}

export interface IntegrationsTabWithCount extends IntegrationsTab {
  /** Undefined while the category's list is still loading. */
  count: number | undefined;
}

/**
 * The Integrations tabs this user may see, in display order.
 *
 * Ordered by how often a category is configured, with the two auto-discovered
 * ones last. Each keeps the exact gate its standalone page carried before the
 * merge, so nothing becomes visible to anyone who could not already reach it:
 *
 *   - Apps: the `integration:read` permission plus INTEGRATIONS.
 *   - DNS providers: `credential:read` plus CREDENTIALS_MANAGEMENT.
 *   - Deployment targets: the same, plus CERTIFICATE_DEPLOYMENT - the old
 *     credentials page hid deployment rows outright when that flag was off.
 *   - Certificate authorities: the DNS providers gate (for the CA accounts
 *     list) or the Device sources gate (for device CA connectors).
 *   - Device sources: enterprise deployment, an organization context, and
 *     IOT_DEVICE_MANAGEMENT.
 *
 * The route rules in `auth-provider` enforce the same gates on direct
 * navigation - this hook only decides what to draw. It deliberately fetches
 * nothing: the sidebar calls it on every page, and nav should not cost four
 * list requests.
 *
 * @returns the visible tabs, plus `isReady` once feature flags have loaded.
 *   Gate "this user has no tabs at all" decisions on `isReady`, otherwise a
 *   flag-gated tab flashes in and out during the first load.
 */
export function useIntegrationsTabs(): {
  tabs: IntegrationsTab[];
  isReady: boolean;
} {
  const { user } = useAuth();
  const { isEnabled, isReady } = useFeatureFlags();
  const { canViewSavedConnections, canViewAgentAdvertised } =
    useIntegrationsAccess();

  const tabs = useMemo(() => {
    const visible: IntegrationsTab[] = [];

    if (canViewIntegrations(user) && isEnabled(FEATURE_FLAGS.INTEGRATIONS)) {
      visible.push({
        id: "apps",
        href: INTEGRATIONS_APPS_HREF,
        label: "Apps",
        autoDiscovered: false,
      });
    }

    if (canViewSavedConnections) {
      visible.push({
        id: "dns",
        href: INTEGRATIONS_DNS_HREF,
        label: "DNS Providers",
        autoDiscovered: false,
      });
    }

    if (
      canViewSavedConnections &&
      isEnabled(FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT)
    ) {
      visible.push({
        id: "deployment-targets",
        href: INTEGRATIONS_DEPLOYMENT_TARGETS_HREF,
        label: "Deployment Targets",
        autoDiscovered: false,
      });
    }

    // Certificate authorities holds two lists: the CA accounts (credential
    // gate) and the agent-advertised device CA connectors (enterprise gate).
    // The tab shows when either one is visible.
    if (canViewSavedConnections || canViewAgentAdvertised) {
      visible.push({
        id: "certificate-authorities",
        href: INTEGRATIONS_CERTIFICATE_AUTHORITIES_HREF,
        label: "Certificate authorities",
        autoDiscovered: !canViewSavedConnections,
      });
    }

    if (canViewAgentAdvertised) {
      visible.push({
        id: "device-sources",
        href: INTEGRATIONS_DEVICE_SOURCES_HREF,
        label: "Device sources",
        autoDiscovered: true,
      });
    }

    return visible;
  }, [canViewAgentAdvertised, canViewSavedConnections, isEnabled, user]);

  return { tabs, isReady };
}

/**
 * The two shared gates behind several Integrations tabs.
 *
 *   - `canViewSavedConnections`: `credential:read` plus CREDENTIALS_MANAGEMENT.
 *     Covers saved connections and the CA accounts list.
 *   - `canViewAgentAdvertised`: enterprise deployment, an organization
 *     context, and IOT_DEVICE_MANAGEMENT.
 */
export function useIntegrationsAccess(): {
  canViewSavedConnections: boolean;
  canViewAgentAdvertised: boolean;
} {
  const { user } = useAuth();
  const { isEnabled } = useFeatureFlags();
  return {
    canViewSavedConnections:
      canViewCredentials(user) &&
      isEnabled(FEATURE_FLAGS.CREDENTIALS_MANAGEMENT),
    canViewAgentAdvertised:
      isEnterpriseAppMode() &&
      hasOrganizationContext(user) &&
      isEnabled(FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT),
  };
}

/**
 * The visible tabs, each with the number of items in its category.
 *
 * The counts are the point of the landing view: they are what turns a tab bar
 * into "here is everything CertPing connects to, by category". Only the section
 * shell calls this - it costs one list request per visible category, and React
 * Query shares each of those with the panel that renders the same list.
 */
export function useIntegrationsTabCounts(): IntegrationsTabWithCount[] {
  const { tabs } = useIntegrationsTabs();
  const has = (id: IntegrationsTabId) => tabs.some((tab) => tab.id === id);

  const appsQuery = useListIntegrations({ enabled: has("apps") });
  const connectionsQuery = useCredentials({
    enabled: has("dns") || has("deployment-targets"),
  });
  const { canViewSavedConnections, canViewAgentAdvertised } =
    useIntegrationsAccess();
  // The CA tab counts configured CAs when the user can see them, and falls
  // back to the agent-advertised connectors otherwise.
  const authoritiesQuery = useCertificateAuthorities(
    has("certificate-authorities") && canViewSavedConnections,
  );
  const caConnectorsQuery = useCaConnectors({
    enabled:
      has("certificate-authorities") &&
      canViewAgentAdvertised &&
      !canViewSavedConnections,
  });
  const deviceSourcesQuery = useDeviceSources({
    enabled: has("device-sources"),
  });

  const connections = connectionsQuery.data;
  const apps = appsQuery.data;
  const caCount = canViewSavedConnections
    ? authoritiesQuery.data?.filter(
        (authority) => authority.status === "CONFIGURED",
      ).length
    : caConnectorsQuery.data?.length;

  return useMemo(
    () =>
      tabs.map((tab) => {
        switch (tab.id) {
          case "apps":
            return {
              ...tab,
              // Only live connections count. A soft-deleted or errored row is
              // not something the user has connected.
              count: apps?.filter(
                (integration) =>
                  integration.status === "ACTIVE" &&
                  integration.deletedAt == null,
              ).length,
            };
          case "dns":
            return {
              ...tab,
              count: connections && getCredentialTabCount(connections, "DNS"),
            };
          case "deployment-targets":
            return {
              ...tab,
              count:
                connections && getCredentialTabCount(connections, "DEPLOYMENT"),
            };
          case "certificate-authorities":
            return { ...tab, count: caCount };
          case "device-sources":
            return { ...tab, count: deviceSourcesQuery.data?.length };
        }
      }),
    [apps, caCount, connections, deviceSourcesQuery.data, tabs],
  );
}
