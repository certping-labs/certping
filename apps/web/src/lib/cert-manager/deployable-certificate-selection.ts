// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { SSLCertificateListItem } from "@/types/ssl";

const DEPLOYABLE_CERTIFICATE_STATUS_PRIORITY = ["ACTIVE", "RENEWING"] as const;
const STATUSES_WITHOUT_DEPLOYABLE_HISTORY = new Set([
  "ACTIVE",
  "FAILED",
  "REVOKED",
  "EXPIRED",
]);

const normalizeCertificateStatus = (status: string): string =>
  status.trim().toUpperCase();

export const isDeployableCertificateStatus = (status: string): boolean =>
  DEPLOYABLE_CERTIFICATE_STATUS_PRIORITY.some(
    (deployableStatus) =>
      deployableStatus === normalizeCertificateStatus(status),
  );

export const getLifecycleHistoryIdsToResolve = (
  certificates: readonly SSLCertificateListItem[],
): Array<string | number> => {
  const historyIds = new Set<string | number>();

  certificates.forEach((certificate) => {
    const status = normalizeCertificateStatus(certificate.status);
    if (
      certificate.userDomainCertId &&
      !STATUSES_WITHOUT_DEPLOYABLE_HISTORY.has(status)
    ) {
      historyIds.add(certificate.userDomainCertId);
    }
  });

  return Array.from(historyIds);
};

const getCertificateLifecycleKey = (
  certificate: SSLCertificateListItem,
): string =>
  certificate.domain.trim()
    ? `domain:${certificate.domain.trim().toLowerCase()}`
    : `udc:${certificate.userDomainCertId ?? certificate.certificateXref ?? ""}`;

const chooseDeployableCertificate = (
  certificates: SSLCertificateListItem[],
): SSLCertificateListItem | undefined => {
  for (const status of DEPLOYABLE_CERTIFICATE_STATUS_PRIORITY) {
    const match = certificates.find(
      (certificate) =>
        normalizeCertificateStatus(certificate.status) === status,
    );
    if (match) {
      return match;
    }
  }

  return undefined;
};

const hasDeployableIdentifier = (
  certificate: SSLCertificateListItem,
): boolean =>
  isDeployableCertificateStatus(certificate.status) &&
  certificate.keyCustody !== "CUSTOMER_HELD" &&
  Boolean(certificate.certificateXref || certificate.domain);

export const getDeployableCertificates = (
  certificates: SSLCertificateListItem[],
): SSLCertificateListItem[] => {
  const groupedCertificates = new Map<string, SSLCertificateListItem[]>();

  certificates.forEach((certificate) => {
    const lifecycleKey = getCertificateLifecycleKey(certificate);
    groupedCertificates.set(lifecycleKey, [
      ...(groupedCertificates.get(lifecycleKey) ?? []),
      certificate,
    ]);
  });

  return Array.from(groupedCertificates.values())
    .map(chooseDeployableCertificate)
    .filter(
      (certificate): certificate is SSLCertificateListItem =>
        certificate !== undefined && hasDeployableIdentifier(certificate),
    );
};

export const resolveDeployableCertificateXref = (
  certificates: SSLCertificateListItem[],
  requestedCertificateId?: string,
): string | undefined => {
  if (!requestedCertificateId) {
    return undefined;
  }

  const requestedCertificate = certificates.find(
    (certificate) =>
      certificate.certificateXref === requestedCertificateId ||
      certificate.domain === requestedCertificateId ||
      certificate.userDomainCertId === requestedCertificateId ||
      String(certificate.id ?? "") === requestedCertificateId,
  );
  if (!requestedCertificate) {
    return undefined;
  }

  const lifecycleKey = getCertificateLifecycleKey(requestedCertificate);
  const lifecycleCertificates = certificates.filter(
    (certificate) => getCertificateLifecycleKey(certificate) === lifecycleKey,
  );
  const deployableCertificate = chooseDeployableCertificate(
    lifecycleCertificates,
  );

  return (
    deployableCertificate?.certificateXref || deployableCertificate?.domain
  );
};
