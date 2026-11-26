// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import tools.jackson.databind.JsonNode;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * A single certificate record returned by the agent inside {@link CertDiscoveryResponse}.
 *
 * <p>Field names mirror the agent's {@code DiscoveredCertEntry} exactly so that
 * Jackson round-trips cleanly through the message queue without mapping config.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class DiscoveredCertEntry {

    /** Provider-native resource identifier (e.g. ACM certificate ARN). */
    private String resourceId;

    /** Primary domain name (CN or first SAN). */
    private String domain;

    /** Key algorithm reported by the provider (e.g. RSA-2048, EC_prime256v1). */
    private String keyAlgorithm;

    /** Signature algorithm (e.g. SHA256WITHRSA). */
    private String signatureAlgorithm;

    /** Certificate validity start in ISO-8601 format. */
    private String notBefore;

    /** Certificate expiry in ISO-8601 format. */
    private String notAfter;

    /** Issuer distinguished name or common name. */
    private String issuer;

    /** Serial number in hex colon-delimited format. */
    private String serialNumber;

    /** Provider-reported certificate status (e.g. ISSUED, EXPIRED, REVOKED). */
    private String certStatus;

    /** Provider resources currently using this certificate (e.g. ALB listener ARNs). */
    private List<String> inUseBy;

    /**
     * Full subject distinguished name (e.g. "CN=test.example.net,O=CertPing Test").
     * Required by CycloneDX 1.6 CBOM certificateProperties.subjectName.
     */
    private String subjectDn;

    /**
     * Subject Alternative Names — all domains this certificate covers.
     */
    private List<String> sanDomains;

    /**
     * Key usage flags as a comma-separated string
     * (e.g. "DIGITAL_SIGNATURE,KEY_ENCIPHERMENT").
     * Used for HNDL risk classification.
     */
    private String keyUsage;

    /**
     * Extended key usage flags as a comma-separated string
     * (e.g. "TLS_WEB_SERVER_AUTHENTICATION").
     */
    private String extendedKeyUsage;

    /**
     * Certificate origin as reported by the provider
     * (e.g. "AMAZON_ISSUED", "IMPORTED", "PRIVATE").
     */
    private String certType;

    /**
     * Kubernetes-specific usage and impact details returned for KUBERNETES_SECRETS discovery.
     */
    private JsonNode kubernetesData;
}
