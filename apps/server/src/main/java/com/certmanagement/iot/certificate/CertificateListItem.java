// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import java.time.OffsetDateTime;

/**
 * One row in the certificate inventory list. {@code status} is the display status
 * (ISSUED, EXPIRING, or EXPIRED) derived from {@code validTo}, not the raw stored value — see
 * {@link IotCertificateQueryService#displayStatus}.
 */
public record CertificateListItem(
        String certificateXref,
        String commonName,
        String serialNumber,
        String status,
        OffsetDateTime validFrom,
        OffsetDateTime validTo,
        OffsetDateTime issuedAt,
        long remainingDays,
        String caProvider,
        String caName,
        String issuerDn,
        String certificateScope,
        CertificateDeviceSummary device,
        CertificateProfileSummary profile,
        String keyAlgorithm,
        Integer keySize,
        String signatureAlgorithm,
        String signatureAlgorithmOid,
        String renewalState,
        Integer nudgeAttempts,
        OffsetDateTime lastNudgedAt,
        String lastNudgeOutcome) {
}
