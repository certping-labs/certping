// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { PlusIcon } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import React from "react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { canCreateCertificates } from "@/lib/authz";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth-store";
import type { SSLCertificateListItem } from "@/types/ssl";

interface CertificateReferenceSelectProps extends Omit<
  React.ComponentPropsWithoutRef<typeof SelectTrigger>,
  "children"
> {
  certificates: readonly SSLCertificateListItem[];
  onValueChange: (value: string) => void;
  value?: string;
}

const ISSUE_CERTIFICATE_ACTION_VALUE = "__issue_certificate__";

const getCertificateValue = (certificate: SSLCertificateListItem): string =>
  certificate.certificateXref || certificate.domain;

export const CertificateReferenceSelect = React.forwardRef<
  React.ElementRef<typeof SelectTrigger>,
  CertificateReferenceSelectProps
>(
  (
    { certificates, className, onValueChange, value, ...selectTriggerProps },
    ref,
  ) => {
    const router = useRouter();
    const isIssuanceOn = useIsFeatureEnabled(
      FEATURE_FLAGS.CERTIFICATE_ISSUANCE,
    );
    const canIssue = useAuthStore((state) => canCreateCertificates(state.user));
    const showIssueAction = isIssuanceOn && canIssue;

    return (
      <Select
        onValueChange={(nextValue) => {
          if (nextValue === ISSUE_CERTIFICATE_ACTION_VALUE) {
            router.push("/cert-manager/add");
            return;
          }

          onValueChange(nextValue);
        }}
        value={value}
      >
        <SelectTrigger
          ref={ref}
          className={cn("h-10 min-w-0 [&>span]:truncate", className)}
          {...selectTriggerProps}
        >
          <SelectValue placeholder="Select a certificate" />
        </SelectTrigger>
        <SelectContent>
          {certificates.map((certificate) => (
            <SelectItem
              key={getCertificateValue(certificate)}
              value={getCertificateValue(certificate)}
            >
              {certificate.domain}
            </SelectItem>
          ))}
          {showIssueAction ? (
            <>
              <SelectSeparator />
              <SelectItem
                className="font-medium text-primary"
                value={ISSUE_CERTIFICATE_ACTION_VALUE}
              >
                <span className="flex items-center gap-2">
                  <PlusIcon className="h-4 w-4" />
                  Issue a certificate
                </span>
              </SelectItem>
            </>
          ) : null}
        </SelectContent>
      </Select>
    );
  },
);
CertificateReferenceSelect.displayName = "CertificateReferenceSelect";
