// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getCertificateManagementState } from "@/lib/certificate-management";
import type { ManagedCertificateSummary } from "@/types/cert-manager";
import type { SSLCertificateListItem } from "@/types/ssl";

/** Converts the backend certificate summary into the shared list-row model. */
export function toSslCertificateListItem(
  certificate: ManagedCertificateSummary,
): SSLCertificateListItem {
  return {
    id: undefined,
    certificateXref: certificate.certificateXref,
    userDomainCertId: certificate.userDomainCertId,
    domain: certificate.domain,
    status: certificate.status,
    rawStatus: certificate.rawStatus,
    caProvider: certificate.caProvider,
    issuer: certificate.issuer,
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    wildcard: certificate.wildcard,
    san: certificate.san,
    sanDomains: certificate.sanDomains,
    dnsConfigXref: certificate.dnsConfigXref,
    deploymentCredentialXrefs: certificate.deploymentCredentialXrefs,
    managementState: getCertificateManagementState(certificate),
    createdAt: certificate.createdAt,
    updatedAt: certificate.updatedAt,
    exportAvailable: certificate.exportAvailable === true,
    keyCustody: certificate.keyCustody,
  };
}
