// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, {
  type MouseEvent,
  type ReactNode,
  useMemo,
  useState,
} from "react";
import { useRouter } from "next/navigation";

import { CredentialDetailsDialog } from "@/components/cert-manager/credential-details-dialog";
import { useCredentials } from "@/hooks/credentials";
import {
  useIsFeatureEnabled,
  useIsRouteAvailable,
} from "@/hooks/use-feature-flags";
import { canUpdateCredentials } from "@/lib/authz";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth-store";

interface CredentialReferenceTriggerProps {
  credentialXref: string;
  children?: ReactNode;
  className?: string;
  ariaLabel?: string;
}

export function CredentialReferenceTrigger({
  credentialXref,
  children,
  className,
  ariaLabel,
}: CredentialReferenceTriggerProps) {
  const router = useRouter();
  const { user } = useAuthStore();
  const [isOpen, setIsOpen] = useState(false);
  const credentialsQuery = useCredentials({ enabled: isOpen });
  const credential = useMemo(
    () =>
      credentialsQuery.data?.find(
        (item) =>
          item.credentialXref === credentialXref ||
          item.alias === credentialXref,
      ) ?? null,
    [credentialXref, credentialsQuery.data],
  );
  const isDnsCredentialsEnabled = useIsFeatureEnabled(
    FEATURE_FLAGS.DNS_CREDENTIALS,
  );
  const isRouteAvailable = useIsRouteAvailable();
  const editHref = credential
    ? `/integrations/connections/${encodeURIComponent(
        credential.credentialXref || credential.alias,
      )}/edit`
    : null;
  // A DNS credential is edited only while DNS_CREDENTIALS is on, and only where the edit page is.
  const canEditCredential =
    canUpdateCredentials(user) &&
    (credential?.type !== "DNS" || isDnsCredentialsEnabled) &&
    editHref !== null &&
    isRouteAvailable(editHref);

  const openDetails = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    setIsOpen(true);
  };

  return (
    <>
      <button
        type="button"
        className={cn(
          "text-primary underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-hidden",
          className,
        )}
        aria-label={ariaLabel || `View credential ${credentialXref}`}
        onClick={openDetails}
      >
        {children ?? credentialXref}
      </button>
      <CredentialDetailsDialog
        credential={credential}
        open={isOpen}
        loading={credentialsQuery.isLoading || credentialsQuery.isFetching}
        canEditCredential={canEditCredential}
        onClose={() => setIsOpen(false)}
        onEdit={
          canEditCredential
            ? () => {
                setIsOpen(false);
                if (editHref) router.push(editHref);
              }
            : undefined
        }
      />
    </>
  );
}
