// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import java.time.OffsetDateTime;
import java.util.List;

public record CertificateDetail(
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
        String subjectDn,
        List<ScepCertificateIssuedMessage.SubjectAlternativeName> subjectAlternativeNames,
        List<String> keyUsages,
        List<String> extendedKeyUsageOids,
        List<String> certificatePolicyOids,
        String keyAlgorithm,
        Integer keySize,
        String publicKeyCurve,
        String signatureAlgorithm,
        String signatureAlgorithmOid,
        String subjectKeyIdentifier,
        String authorityKeyIdentifier,
        String fingerprintSha256,
        boolean certificateAuthority,
        String caEndEntityName,
        String caProvisionerName,
        EnrollmentSummary enrollment,
        CertificateDeviceSummary device,
        CertificateProfileSummary profile,
        String renewalState,
        Integer nudgeAttempts,
        OffsetDateTime lastNudgedAt,
        String lastNudgeOutcome) {

    public record EnrollmentSummary(
            String enrollmentXref,
            String enrollmentType,
            String transactionId,
            String status,
            String deviceMatchStatus,
            String profileResolutionStatus,
            String priorCertificateSerialNumber,
            OffsetDateTime requestedAt,
            OffsetDateTime validatedAt,
            OffsetDateTime issuedAt,
            OffsetDateTime completedAt) {
    }
}
