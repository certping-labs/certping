// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.CertType;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Received from certping-agent on cert-agent-outbound with MessageType=CERT_ISSUANCE_RESPONSE.
 *
 * status field:
 *   "ISSUED"  — new certificate successfully issued
 *   "RENEWED" — existing certificate successfully renewed (certping-agent reuses this
 *               message type for renewals; there is no separate CERT_RENEWAL_RESPONSE)
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertIssuanceResponse {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;

    /** ISSUED | RENEWED */
    private String status;

    private CaProvider caProvider;
    private String certSecretHandle;

    /**
     * Versioned secret-store handle (with an explicit version, where the store has versions).
     * Passed directly to the deployment command so the agent reads the exact version
     * that was just issued rather than resolving "latest".
     * Null when the agent does not support versioned paths (backwards-compatible).
     */
    private String certSecretHandleWithVersion;

    private String acmeAccountHandle;

    private String issuer;
    private String serialNumber;
    private String fingerprintSha256;
    private String validFrom;
    private String validTo;
    private String signatureAlgorithm;
    private String signatureAlgorithmOid;
    private String subjectDn;
    private String commonName;
    private String publicKeyAlgorithm;
    private Integer keySize;
    private String publicKeyCurve;
    private String keyUsage;
    private String extendedKeyUsage;
    private String subjectKeyIdentifier;
    private String authorityKeyIdentifier;
    private CertType certType;
    private String respondedAt;

    /** CA order identifier when applicable (e.g. DigiCert). */
    private String orderId;

    /** What the CA charged for this order, as sent; absent when the CA reports none. */
    private String caOrderCost;

    /** The currency the CA named for {@link #caOrderCost}; absent when it names none. */
    private String caOrderCurrency;

    /** {@code REPLACEMENT} when the certificate is a reissue on an order already placed; otherwise absent. */
    private String caOrderAction;

    /** {@code PLATFORM_HELD} or {@code CUSTOMER_HELD}; absent from older agents, which always hold the key. */
    private String keyCustody;
}
