// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo } from "react";
import { useSearchParams } from "next/navigation";
import { CertificateRequestForm } from "@/components/cert-manager/add-domain-form";
import { Unauthorised } from "@/components/common/unautorised";
import { CertManagerPageLoading } from "@/components/ui/loading-templates";
import { PageHeader } from "@/components/ui/page-header";
import { useAuth } from "@/hooks/use-auth";
import { useGetCertificateDetails } from "@/hooks/ssl";
import { canCreateCertificates } from "@/lib/authz";
import { certificateRequestPrefill } from "@/lib/cert-manager/certificate-request-form";
import { readDomainParam } from "@/lib/cert-manager/domain-param";

/** CERTIFICATE_ISSUANCE is enforced by `FeatureRouteGate` (see feature-routes). */
export default function AddCertificatePage() {
  const { user, isLoading } = useAuth();
  const canCreateCertificate = canCreateCertificates(user);
  const searchParams = useSearchParams();
  const initialDomain = readDomainParam(searchParams?.get("domain"));
  const wildcardParam = searchParams?.get("wildcard") === "1";
  const sourceCertificateXref = searchParams?.get("from")?.trim() || undefined;
  const canIssue = canCreateCertificate;
  const sourceCertificate = useGetCertificateDetails(
    canIssue && sourceCertificateXref ? sourceCertificateXref : "",
  );
  const sourceCertificateData = sourceCertificate.data;
  const initialValues = useMemo(
    () =>
      sourceCertificateData
        ? certificateRequestPrefill(sourceCertificateData)
        : initialDomain
          ? { domain: initialDomain, wildcard: wildcardParam }
          : undefined,
    [initialDomain, sourceCertificateData, wildcardParam],
  );

  if (isLoading || (canIssue && sourceCertificate.isLoading)) {
    return <CertManagerPageLoading />;
  }

  if (!canCreateCertificate) {
    return (
      <main className="container flex-1 px-4 py-6 md:py-8">
        <Unauthorised />
      </main>
    );
  }

  return (
    <main className="flex-1 space-y-5 p-4 pb-28 sm:p-6 md:pb-36">
      <PageHeader
        title="Issue a certificate"
        subtitle="Certificates that use a connected DNS provider renew automatically, and redeploy to the deployment targets you add."
        breadcrumbs={[{ label: "Certificates", href: "/cert-manager" }]}
      />
      <CertificateRequestForm
        initialDomain={initialDomain}
        initialValues={initialValues}
        sourceCertificateXref={sourceCertificateXref}
      />
    </main>
  );
}
