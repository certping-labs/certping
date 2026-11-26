// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";
import React, { useMemo, useState } from "react";
import { Card } from "@/components/ui/card";
import {
  DetailItem,
  DetailList,
  DetailSection,
} from "@/components/ui/detail-list";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { CredentialDetailsDialog } from "@/components/cert-manager/credential-details-dialog";
import { useCredentials } from "@/hooks/credentials";
import { CredentialRecord, SSLCertificateDetails } from "@/types/ssl";
import { getProviderPresentation } from "@/lib/credential-providers";
import { getPrimaryDnsConfigXref } from "@/lib/certificate-management";
import {
  getCertificateStatusLabel,
  getCertificateStatusTone,
} from "@/lib/cert-manager/certificate-status";
import { getApiErrorMessage } from "@/lib/backend/common";
import { errorReference, withReference } from "@/lib/correlation-id";
import { useCompleteDnsChallenge } from "@/hooks/ssl";
import {
  getValidFrom,
  getValidTo,
  formatCertDate,
  getRemainingDays,
} from "@/lib/utils";
import { WarningIcon, WarningOctagonIcon } from "@phosphor-icons/react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { canCreateCertificates } from "@/lib/authz";
import { issueCertificateHref } from "@/lib/cert-manager/certificate-journeys";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { useAuthStore } from "@/stores/auth-store";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";
import { SupportReferenceLink } from "@/components/support/support-reference-link";

export function CertDetailss({
  certificate,
}: {
  certificate?: SSLCertificateDetails;
}) {
  const validFrom = getValidFrom(certificate || {});
  const validTo = getValidTo(certificate || {});
  const remainingDays = getRemainingDays(validTo);
  const isCertIssuanceEnabled = useIsFeatureEnabled("CERTIFICATE_ISSUANCE");
  const canCreate = useAuthStore((state) => canCreateCertificates(state.user));
  const isManualIssuanceEnabled = useIsFeatureEnabled(
    "CERTIFICATE_MANUAL_ISSUANCE",
  );
  const canRequestAgain = isCertIssuanceEnabled && canCreate;
  // The Credentials section opens credential records, so it lives and dies
  // with credential management.
  const isCredentialsOn = useIsFeatureEnabled("CREDENTIALS_MANAGEMENT");
  const validateDns = useCompleteDnsChallenge();
  const sanDomains = certificate?.sanDomains ?? [];
  const deploymentCredentialXrefs = useMemo(
    () => certificate?.deploymentCredentialXrefs ?? [],
    [certificate?.deploymentCredentialXrefs],
  );
  const dnsConfigXref = getPrimaryDnsConfigXref(
    certificate?.dnsConfigXref,
    certificate?.domain,
  );

  const [selectedCredentialXref, setSelectedCredentialXref] = useState<
    string | null
  >(null);

  const referencedXrefs = useMemo(() => {
    const xrefs = new Set<string>();
    if (dnsConfigXref) {
      xrefs.add(dnsConfigXref);
    }
    deploymentCredentialXrefs.forEach((xref) => xrefs.add(xref));
    return xrefs;
  }, [dnsConfigXref, deploymentCredentialXrefs]);

  const credentialsQuery = useCredentials({
    enabled: isCredentialsOn && referencedXrefs.size > 0,
  });

  const credentialsByXref = useMemo(() => {
    const map = new Map<string, CredentialRecord>();
    (credentialsQuery.data ?? []).forEach((credential) => {
      const key = credential.credentialXref || credential.alias;
      if (key) {
        map.set(key, credential);
      }
    });
    return map;
  }, [credentialsQuery.data]);

  const selectedCredential = selectedCredentialXref
    ? (credentialsByXref.get(selectedCredentialXref) ?? null)
    : null;

  const closeCredentialDialog = () => setSelectedCredentialXref(null);

  const cryptoDetails = [
    { label: "Certificate type", value: certificate?.certType },
    { label: "Public key algorithm", value: certificate?.publicKeyAlgorithm },
    {
      label: "Key size",
      value: certificate?.keySize ? `${certificate.keySize} bits` : undefined,
    },
    { label: "Signature algorithm", value: certificate?.signatureAlgorithm },
  ].filter((item) => !!item.value);

  const identifierDetails = [
    { label: "Serial number", value: certificate?.serialNumber },
    { label: "Fingerprint (SHA-256)", value: certificate?.fingerprintSha256 },
    { label: "CA order", value: certificate?.orderId },
  ].filter((item) => !!item.value);
  const isEnterpriseMode = isEnterpriseAppMode();
  const statusLabel = getCertificateStatusLabel(
    certificate?.status ?? "PENDING",
  );
  const hasCoverage =
    (certificate?.san && sanDomains.length > 0) || certificate?.wildcard;
  const hasReferences =
    isCredentialsOn &&
    (Boolean(dnsConfigXref) || deploymentCredentialXrefs.length > 0);
  const hasBackendState =
    (isEnterpriseMode && Boolean(certificate?.certSecretHandle)) ||
    Boolean(certificate?.userMessage);

  const isFailed = certificate?.status?.toUpperCase() === "FAILED";
  const canCheckDnsAgain =
    isFailed &&
    !dnsConfigXref &&
    Boolean(certificate?.certificateXref) &&
    isManualIssuanceEnabled &&
    canCreate;
  const validateDnsError = validateDns.isError
    ? withReference(
        getApiErrorMessage(
          validateDns.error,
          "The DNS records could not be checked.",
        ),
        errorReference(validateDns.error),
      )
    : null;

  return (
    <div className="space-y-5">
      {isFailed ? (
        <section
          aria-label="Issuance failed"
          className="flex flex-col gap-4 rounded-xl border border-danger-border bg-danger-soft p-5 lg:flex-row lg:items-center"
        >
          <WarningOctagonIcon
            aria-hidden
            weight="fill"
            className="size-7 shrink-0 text-danger-foreground"
          />
          <div className="min-w-0 flex-1 space-y-1">
            <h2 className="text-base font-semibold text-foreground">
              This certificate failed to issue
            </h2>
            <p className="text-sm text-foreground/80">
              {certificate?.userMessage ??
                "The certificate authority did not complete the request."}{" "}
              {certificate?.domain
                ? `${certificate.domain} is not covered until a certificate is issued.`
                : null}
            </p>
            {canCheckDnsAgain ? (
              <p className="text-sm text-foreground/80">
                If the TXT records are still published, check them again. If the
                validation window has closed, request the certificate again.
              </p>
            ) : null}
            {certificate?.lastErrorAt ? (
              <p className="text-xs text-foreground/70">
                Failed {formatCertDate(certificate.lastErrorAt)}
              </p>
            ) : null}
            {validateDnsError ? (
              <p
                role="alert"
                className="text-sm font-medium text-danger-foreground"
              >
                {validateDnsError}
              </p>
            ) : null}
          </div>
          <div className="flex flex-col gap-2 sm:flex-row lg:flex-col xl:flex-row">
            {canCheckDnsAgain && certificate?.certificateXref ? (
              <Button
                className="h-11 px-6 text-[15px]"
                isPending={validateDns.isPending}
                disabled={validateDns.isPending}
                onClick={() =>
                  validateDns.mutate({
                    certificateXref: certificate.certificateXref ?? "",
                  })
                }
              >
                Check DNS records again
              </Button>
            ) : null}
            {certificate?.domain && canRequestAgain ? (
              <Button
                asChild
                variant={canCheckDnsAgain ? "outline" : "default"}
                className="h-11 px-6 text-[15px]"
              >
                <Link
                  href={issueCertificateHref({
                    domain: certificate.domain,
                    wildcard: certificate.wildcard,
                    from: certificate.certificateXref,
                  })}
                >
                  Request it again
                </Link>
              </Button>
            ) : null}
          </div>
        </section>
      ) : null}

      {certificate?.status === "ACTIVE" &&
        remainingDays !== null &&
        remainingDays <= 30 &&
        remainingDays > 0 && (
          <Alert variant="warning">
            <WarningIcon />
            <AlertDescription>
              <span className="font-medium">
                Certificate expires in {remainingDays} days
              </span>
              <p className="mt-0.5">
                Renew before {formatCertDate(validTo)} to keep the service
                available.
              </p>
            </AlertDescription>
          </Alert>
        )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px] xl:items-start">
        <Card>
          <DetailSection title="Certificate">
            <DetailList>
              <DetailItem label="Domain" mono>
                {certificate?.domain}
              </DetailItem>
              <DetailItem label="Status">
                <Badge
                  variant={getCertificateStatusTone(
                    certificate?.status ?? "PENDING",
                  )}
                >
                  {statusLabel}
                </Badge>
              </DetailItem>
              <DetailItem label="Type">
                {certificate?.wildcard || certificate?.san ? (
                  <span className="flex flex-wrap gap-1.5">
                    {certificate?.wildcard ? (
                      <Badge variant="secondary">Wildcard</Badge>
                    ) : null}
                    {certificate?.san ? (
                      <Badge variant="secondary">Multi-domain</Badge>
                    ) : null}
                  </span>
                ) : (
                  "Single domain"
                )}
              </DetailItem>
              <DetailItem label="Issuer">{certificate?.issuer}</DetailItem>
              <DetailItem label="CA provider">
                {certificate?.caProvider
                  ? getProviderPresentation(certificate.caProvider).label
                  : "Not assigned"}
              </DetailItem>
            </DetailList>
          </DetailSection>

          {cryptoDetails.length ? (
            <DetailSection title="Cryptography">
              <DetailList>
                {cryptoDetails.map((item) => (
                  <DetailItem
                    key={item.label}
                    label={item.label}
                    mono={item.label.includes("algorithm")}
                  >
                    {item.value}
                  </DetailItem>
                ))}
              </DetailList>
            </DetailSection>
          ) : null}

          {identifierDetails.length ? (
            <DetailSection title="Identifiers">
              <DetailList>
                {identifierDetails.map((item) => (
                  <DetailItem key={item.label} label={item.label} mono>
                    {item.value}
                  </DetailItem>
                ))}
              </DetailList>
            </DetailSection>
          ) : null}

          {hasCoverage ? (
            <DetailSection
              title="Domain coverage"
              description={
                certificate?.wildcard
                  ? "Wildcard: covers every first-level subdomain, for example app.example.com under *.example.com."
                  : undefined
              }
            >
              <DetailList>
                <DetailItem label="Primary domain" mono>
                  {certificate?.domain}
                </DetailItem>
                {certificate?.san && sanDomains.length > 0 ? (
                  <DetailItem
                    label={`Alternative names (${sanDomains.length})`}
                  >
                    <ul className="max-h-48 space-y-1 overflow-y-auto font-mono text-[13px]">
                      {sanDomains.map((domain) => (
                        <li key={domain} className="break-all">
                          {domain}
                        </li>
                      ))}
                    </ul>
                  </DetailItem>
                ) : null}
              </DetailList>
            </DetailSection>
          ) : null}
        </Card>

        <Card>
          <DetailSection title="Validity">
            <DetailList className="sm:grid-cols-[minmax(6rem,8rem)_minmax(0,1fr)]">
              <DetailItem label="Valid from">
                {formatCertDate(validFrom)}
              </DetailItem>
              <DetailItem label="Valid until">
                {formatCertDate(validTo)}
              </DetailItem>
              {remainingDays !== null ? (
                <DetailItem label="Remaining">
                  {remainingDays > 0 ? `${remainingDays} days` : "Expired"}
                </DetailItem>
              ) : null}
            </DetailList>
          </DetailSection>

          {hasReferences ? (
            <DetailSection title="Credentials">
              <DetailList className="sm:grid-cols-[minmax(6rem,8rem)_minmax(0,1fr)]">
                {dnsConfigXref ? (
                  <DetailItem label="DNS">
                    <button
                      type="button"
                      onClick={() => setSelectedCredentialXref(dnsConfigXref)}
                      className="text-left font-mono text-[13px] break-all text-primary hover:underline focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
                    >
                      {dnsConfigXref}
                    </button>
                  </DetailItem>
                ) : null}
                {deploymentCredentialXrefs.length > 0 ? (
                  <DetailItem label="Deployment">
                    <span className="flex flex-col items-start gap-1">
                      {deploymentCredentialXrefs.map((credentialXref) => (
                        <button
                          key={credentialXref}
                          type="button"
                          onClick={() =>
                            setSelectedCredentialXref(credentialXref)
                          }
                          className="text-left font-mono text-[13px] break-all text-primary hover:underline focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
                        >
                          {credentialXref}
                        </button>
                      ))}
                    </span>
                  </DetailItem>
                ) : null}
              </DetailList>
            </DetailSection>
          ) : null}

          {hasBackendState ? (
            <DetailSection title="Last error">
              <DetailList className="sm:grid-cols-1">
                {isEnterpriseMode && certificate?.certSecretHandle ? (
                  <DetailItem label="Certificate secret handle" mono>
                    {certificate.certSecretHandle}
                  </DetailItem>
                ) : null}
                {certificate?.userMessage ? (
                  <DetailItem label="Message">
                    {certificate.userMessage}
                  </DetailItem>
                ) : null}
                {certificate?.lastErrorAt ? (
                  <DetailItem label="When">
                    {formatCertDate(certificate.lastErrorAt)}
                  </DetailItem>
                ) : null}
              </DetailList>
              {certificate?.userMessage ? (
                <SupportReferenceLink
                  correlationId={certificate.correlationId}
                  summary={
                    certificate.domain
                      ? `Certificate error for ${certificate.domain}`
                      : "Certificate error"
                  }
                  message={certificate.userMessage}
                  domain={certificate.domain}
                />
              ) : null}
            </DetailSection>
          ) : null}
        </Card>
      </div>

      <CredentialDetailsDialog
        credential={selectedCredential}
        open={Boolean(selectedCredentialXref)}
        loading={credentialsQuery.isLoading || credentialsQuery.isFetching}
        onClose={closeCredentialDialog}
      />
    </div>
  );
}
