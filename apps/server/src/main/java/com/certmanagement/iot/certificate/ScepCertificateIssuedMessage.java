// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/** Metadata-only agent-to-server result. Certificate PEM, DER, chains, CSRs, and secrets are forbidden. */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScepCertificateIssuedMessage {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    /** Device-source route that served the request. */
    private String connectionProfileRef;
    /** Optional corroboration: must resolve to the same source as connectionProfileRef, else rejected. */
    private String sourceXref;
    private String endpointId;
    /** Optional certificate-profile hint — never a routing key. */
    private String profileXref;
    /** Optional provider-native profile id hint — never a routing key. */
    private String providerProfileId;
    private String intuneTransactionId;
    private String csrFingerprintSha256;
    /** Device identifier with explicit provenance; absent when the request revealed none. */
    private DeviceIdentifier deviceIdentifier;
    private String enrollmentType;
    private String priorCertificateIssuerDn;
    private String priorCertificateSerialNumber;
    private String caProvider;
    private String caName;
    private String endEntityName;
    private String caProvisionerName;
    private String issuer;
    private String serialNumber;
    private String status;
    private String subjectDn;
    private String commonName;
    private List<SubjectAlternativeName> subjectAltNames;
    private String fingerprintSha1;
    private String fingerprintSha256;
    private String validFrom;
    private String validTo;
    private String signatureAlgorithm;
    private String signatureAlgorithmOid;
    private String publicKeyAlgorithm;
    private Integer keySize;
    private String publicKeyCurve;
    private String keyUsage;
    private String extendedKeyUsage;
    private List<String> certificatePolicyOids;
    private Boolean certificateAuthority;
    private String subjectKeyIdentifier;
    private String authorityKeyIdentifier;
    private String requestedAt;
    private String validatedAt;
    private String issuedAt;
    private String completedAt;
    private String respondedAt;

    public record SubjectAlternativeName(String type, String oid, String value) {
    }

    /** Identifier facts with provenance; only MICROSOFT_VALIDATED may ever auto-link a device. */
    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DeviceIdentifier {
        private String value;
        private String type;
        private String assurance;
        private String provider;
    }
}
