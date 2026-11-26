// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Outbound response — Agent → Server. MessageType = "SCEP_CERT_ISSUED" (set as an application
 * property, not a body field). Message version 3: routing is source-first.
 *
 * <p>Sent after a device certificate is issued over SCEP so the server can record it, tie it to the
 * managed device, and later revoke it. The data is read from the <em>issued leaf certificate</em> (in
 * the Intune flow the subject and all four SAN types pass through the CSR into the certificate), plus
 * the correlation identifiers the certificate does not carry: the Intune {@code transactionId}, the
 * {@code connectionProfileRef} of the source route that served the request, and the EJBCA
 * {@code endEntityName}. The revocation key is {@code issuer} DN + {@code serialNumber}.
 *
 * <p>{@code profileXref} and {@code providerProfileId} are optional hints only — never routing
 * keys, and never derived from the endpoint id. The server persists the certificate under the
 * resolved device source even when the certificate profile is unknown and reconciles the profile
 * later from deterministic evidence.
 *
 * <p>No private key and no {@code challengePassword} appear here by design — the device holds the key,
 * and the challenge is a secret that is never transmitted or logged.
 */
@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScepCertIssuedResponse {

    private Integer messageVersion;

    // Routing / correlation — source-first, never profile-first
    private String requestId;
    private String correlationId;
    private String organizationId;
    /** The device-source connection that served the request; equals the registered route key. */
    private String connectionProfileRef;
    /** Optional server source xref corroboration; the agent does not know it and sends null. */
    private String sourceXref;
    /** The literal route key the device called — {@code connectionProfileRef} or the default alias. */
    private String endpointId;
    /** Optional certificate-profile hint. Null unless the exact profile is actually known. */
    private String profileXref;
    /** Optional provider-native profile id hint. Null unless actually known. */
    private String providerProfileId;
    private String intuneTransactionId;
    private String csrFingerprintSha256;
    /** Device identifier with explicit provenance; null when no identifier was revealed. */
    private DeviceIdentifier deviceIdentifier;
    private String enrollmentType;
    private String priorCertificateIssuerDn;
    private String priorCertificateSerialNumber;

    // CA identity + revocation key
    private CaProvider caProvider;
    private String caName;
    /** The name the CA filed the device under (EJBCA end entity) — the operator's search key. */
    private String endEntityName;
    /** Smallstep provisioner used to authorize issuance; null for EJBCA. */
    private String caProvisionerName;
    /** Issuer distinguished name; with {@link #serialNumber} this is the revocation key. */
    private String issuer;
    private String serialNumber;
    private String status;

    // Certificate metadata (parsed from the issued leaf)
    private String subjectDn;
    private String commonName;
    /** Structured subject alternative names with stable type, optional otherName OID, and value. */
    private List<CertificateSubjectAlternativeName> subjectAltNames;
    /** SHA-1 is retained only for exact Intune report correlation; SHA-256 remains the integrity key. */
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
    private String subjectKeyIdentifier;
    private String authorityKeyIdentifier;
    private List<String> certificatePolicyOids;
    private Boolean certificateAuthority;

    private String requestedAt;
    private String validatedAt;
    private String issuedAt;
    private String completedAt;
    private String respondedAt;

    /**
     * Identifier facts with provenance. {@code assurance} is {@code MICROSOFT_VALIDATED} only when
     * the DeviceId tamper test has proven Microsoft validation covers the field; an identifier that
     * is merely visible in the request travels as {@code ASSERTED} and never auto-links a device.
     */
    @Data
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DeviceIdentifier {
        private String value;
        /** MANAGED_DEVICE_ID, ENTRA_DEVICE_ID, ENTRA_OBJECT_ID, or UNKNOWN. */
        private String type;
        /** MICROSOFT_VALIDATED or ASSERTED (ABSENT is expressed by omitting the whole object). */
        private String assurance;
        /** Identifier namespace owner, e.g. INTUNE. */
        private String provider;
    }
}
