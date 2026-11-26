// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { Unauthorised } from "@/components/common/unautorised";
import { CertificateAuthoritiesPanel } from "@/components/integrations/agent-advertised-panels";
import { CertificateAuthoritiesSection } from "@/components/integrations/certificate-authorities/certificate-authorities-section";
import { useIntegrationsAccess } from "@/components/integrations/use-integrations-tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { useFeatureFlags } from "@/hooks/use-feature-flags";

/**
 * The Certificate authorities tab: the CA accounts the organization issues
 * from (credential viewers), then the device CA connectors agents advertise
 * (enterprise with device management on). Each list keeps its own gate.
 */
export function CertificateAuthorityAccessPanels() {
  const { isReady } = useFeatureFlags();
  const { canViewSavedConnections, canViewAgentAdvertised } =
    useIntegrationsAccess();

  if (!canViewSavedConnections && !canViewAgentAdvertised) {
    return isReady ? <Unauthorised /> : <Skeleton className="h-48 w-full" />;
  }

  return (
    <div className="space-y-8">
      {canViewSavedConnections ? <CertificateAuthoritiesSection /> : null}
      {canViewAgentAdvertised ? (
        <CertificateAuthoritiesPanel
          title={
            canViewSavedConnections
              ? "Device CA connectors"
              : "Certificate authorities"
          }
        />
      ) : null}
    </div>
  );
}
