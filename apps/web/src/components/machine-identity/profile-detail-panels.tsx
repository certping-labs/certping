// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import {
  DefinitionList,
  DetailEmptyState,
  DetailPanel,
} from "@/components/machine-identity/detail-panel";
import { PROFILE_ORIGIN_LABELS } from "@/lib/machine-identity/backend-display";
import { humanizeConstant, pluralize } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type { CertificateProfileResponse } from "@/types/machine-identity-backend";

/** Configuration and provider-sync panels for the certificate profile detail page. */
export function ProfileConfigurationPanel({
  profile,
}: {
  profile: CertificateProfileResponse;
}) {
  const cfg = profile.configuration;
  if (!cfg) {
    return (
      <DetailPanel title="Configuration">
        <DetailEmptyState message="No configuration recorded." />
      </DetailPanel>
    );
  }

  return (
    <DetailPanel title="Configuration">
      <DefinitionList
        items={[
          {
            label: "Certificate scope",
            value: cfg.certificateScope
              ? humanizeConstant(cfg.certificateScope)
              : null,
          },
          {
            label: "Key",
            value:
              cfg.keyAlgorithm === null
                ? null
                : cfg.keyAlgorithm === "EC"
                  ? ["EC", cfg.curve].filter(Boolean).join(" ")
                  : ["RSA", cfg.keySize].filter(Boolean).join(" "),
          },
          { label: "Signature hash", value: cfg.signatureHash },
          {
            label: "Subject format",
            value: cfg.subjectNameFormat,
            monospace: true,
          },
          {
            label: "SAN entries",
            value:
              cfg.subjectAltNameFormats.length === 0
                ? "None"
                : cfg.subjectAltNameFormats
                    .map((san) => `${san.type}: ${san.format}`)
                    .join("; "),
            monospace: true,
          },
          { label: "Key usages", value: cfg.keyUsages.join(", ") || null },
          {
            label: "Validity",
            value:
              cfg.validityValue && cfg.validityUnit
                ? pluralize(
                    cfg.validityValue,
                    // "DAYS" -> "day", so a one-day profile is not "1 days".
                    humanizeConstant(cfg.validityUnit)
                      .toLowerCase()
                      .replace(/s$/, ""),
                  )
                : null,
          },
          {
            label: "Renewal window",
            value:
              cfg.renewalWindowDays !== null
                ? `${pluralize(cfg.renewalWindowDays, "day")} before expiry`
                : null,
          },
        ]}
      />
    </DetailPanel>
  );
}

export function ProfileSyncPanel({
  profile,
}: {
  profile: CertificateProfileResponse;
}) {
  return (
    <DetailPanel title="Provider sync">
      <DefinitionList
        items={[
          {
            label: "Origin",
            value: PROFILE_ORIGIN_LABELS[profile.profileOrigin],
          },
          {
            label: "Provider profile type",
            value: profile.providerProfileType,
          },
          {
            label: "Provider profile ID",
            value: profile.providerProfileId,
            monospace: true,
          },
          {
            label: "Last synced",
            value: profile.lastProviderSyncedAt
              ? formatDateTimeCompact(profile.lastProviderSyncedAt)
              : "Never",
          },
          {
            label: "Latest operation",
            value: profile.latestOperationStartedAt
              ? profile.latestOperationCompletedAt
                ? `Completed ${formatDateTimeCompact(profile.latestOperationCompletedAt)}`
                : `In progress since ${formatDateTimeCompact(profile.latestOperationStartedAt)}`
              : null,
          },
          ...(profile.providerSyncError
            ? [{ label: "Last error", value: profile.providerSyncError }]
            : []),
          {
            // A profile discovered from the provider has never had a CertPing
            // revision, and `String(null)` printed the word "null" at the
            // operator.
            label: "Revision",
            value:
              profile.desiredRevision === null
                ? null
                : profile.appliedRevision === null
                  ? `${profile.desiredRevision} desired · none applied yet`
                  : profile.appliedRevision === profile.desiredRevision
                    ? `${profile.desiredRevision} (applied)`
                    : `${profile.desiredRevision} desired · ${profile.appliedRevision} applied`,
          },
        ]}
      />
    </DetailPanel>
  );
}
