// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Value;

import java.util.List;

/**
 * Metadata for a single certificate discovered at a deployment target.
 *
 * <p>The agent reports raw provider metadata only. It does not classify certificates
 * as managed or unmanaged — that cross-reference is performed by the server
 * when it processes the {@link CertDiscoveryResponse}.
 */
@Value
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class DiscoveredCertEntry {

    /** Provider-native resource identifier (e.g. ACM certificate ARN). */
    String resourceId;

    /** Primary domain name (CN or first SAN). */
    String domain;

    /** Key algorithm reported by the provider (e.g. RSA-2048, EC_prime256v1). */
    String keyAlgorithm;

    /** Signature algorithm (e.g. SHA256WITHRSA). */
    String signatureAlgorithm;

    /** Certificate validity start in ISO-8601 format. */
    String notBefore;

    /** Certificate expiry in ISO-8601 format. */
    String notAfter;

    /** Issuer distinguished name or common name. */
    String issuer;

    /** Serial number in hex colon-delimited format. */
    String serialNumber;

    /**
     * Provider-reported certificate status (e.g. ISSUED, EXPIRED, REVOKED).
     * Value is provider-specific — the server normalises it on ingestion.
     */
    String certStatus;

    /**
     * Provider resources currently using this certificate (e.g. ALB listener ARNs).
     * For providers with complete usage inventory, an empty list means no usage was found.
     * Kubernetes consumers must also require {@code kubernetesData.usageComplete=true}; when it is
     * false, an empty list is unknown rather than evidence that the certificate is unused.
     */
    List<String> inUseBy;

    /**
     * Full subject distinguished name (e.g. "CN=test.example.net,O=CertPing Test").
     * Required by CycloneDX 1.6 CBOM certificateProperties.subjectName.
     */
    String subjectDn;

    /**
     * Subject Alternative Names — all domains this certificate covers.
     * Includes the primary domain and any additional SANs.
     */
    List<String> sanDomains;

    /**
     * Key usage flags as a comma-separated string
     * (e.g. "DIGITAL_SIGNATURE,KEY_ENCIPHERMENT").
     * Used for HNDL risk classification: certs with KEY_AGREEMENT or KEY_ENCIPHERMENT
     * are exposed to harvest-now-decrypt-later attacks.
     */
    String keyUsage;

    /**
     * Extended key usage flags as a comma-separated string
     * (e.g. "TLS_WEB_SERVER_AUTHENTICATION,TLS_WEB_CLIENT_AUTHENTICATION").
     */
    String extendedKeyUsage;

    /**
     * Certificate origin as reported by the provider
     * (e.g. "AMAZON_ISSUED", "IMPORTED", "PRIVATE").
     */
    String certType;

    /**
     * Kubernetes-specific source, usage, and impact evidence. This is populated only by
     * Kubernetes discovery adapters so existing non-Kubernetes discovery consumers can keep
     * using the common certificate fields unchanged.
     */
    KubernetesCertificateData kubernetesData;
}
