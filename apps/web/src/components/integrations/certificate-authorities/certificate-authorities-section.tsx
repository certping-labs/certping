// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { CertificateAuthorityCard } from "@/components/integrations/certificate-authorities/certificate-authority-card";
import { IntegrationsTabHeader } from "@/components/integrations/integrations-tab-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useCertificateAuthorities } from "@/hooks/ca-credentials";
import { useAuth } from "@/hooks/use-auth";
import {
  canCreateCredentials,
  canDeleteCredentials,
  canRotateCredentials,
} from "@/lib/authz";
import { getApiErrorMessage } from "@/lib/backend/common";

/**
 * Every CA CertPing can issue from, with where each one is set up.
 *
 * Shows metadata only. ACME account keys stay with the agent and DigiCert
 * keys are write-only, so no key material ever reaches this page.
 */
export function CertificateAuthoritiesSection() {
  const { user } = useAuth();
  const query = useCertificateAuthorities();
  const authorities = query.data ?? [];
  const permissions = {
    canAdd: canCreateCredentials(user),
    // Same permissions the server checks on PUT and DELETE.
    canReplace: canRotateCredentials(user),
    canDelete: canDeleteCredentials(user),
  };

  return (
    <section className="space-y-4" aria-label="Certificate authorities">
      <IntegrationsTabHeader
        title="Certificate authorities"
        description="The CAs CertPing can issue from, and where each one is set up. CertPing never shows private keys or API keys."
      />

      {query.isLoading ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : query.error ? (
        <Alert variant="destructive">
          <AlertTitle>Could not load certificate authorities</AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{getApiErrorMessage(query.error, "Try again in a moment.")}</p>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              Try again
            </Button>
          </AlertDescription>
        </Alert>
      ) : authorities.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border bg-card px-6 py-10 text-center text-sm text-muted-foreground">
          No certificate authorities to show yet.
        </p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          {authorities.map((authority) => (
            <CertificateAuthorityCard
              key={authority.id}
              authority={authority}
              permissions={permissions}
            />
          ))}
        </div>
      )}
    </section>
  );
}
