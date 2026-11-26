// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import java.util.List;

/**
 * Parsed metadata from an issued leaf X509 certificate.
 * All fields are nullable — extraction is best-effort and must not block issuance.
 */
public record CertificateMetadata(
        String signatureAlgorithm,
        String signatureAlgorithmOid,
        String subjectDn,
        String commonName,
        String publicKeyAlgorithm,
        Integer keySize,
        String publicKeyCurve,
        String keyUsage,
        String extendedKeyUsage,
        String subjectKeyIdentifier,
        String authorityKeyIdentifier,
        List<String> certificatePolicyOids,
        Boolean certificateAuthority
) {}
