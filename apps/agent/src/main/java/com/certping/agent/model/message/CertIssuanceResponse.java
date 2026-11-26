// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.enums.CertType;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

/**
 * Outbound message — agent → certping (cert-agent-outbound).
 *
 * <p>The {@code MessageType} is set as an <em>application property</em> by
 * {@link com.certping.agent.listener.AgentMessageSender} — it is NOT a JSON body field.
 * The server routes on the application property, not the body, so no {@code messageType}
 * field is needed here.
 *
 * <p>certping stores {@code certSecretHandle}, {@code acmeAccountHandle}, and {@code orderId} in Postgres.
 * {@code acmeAccountHandle} is null for DigiCert. {@code orderId} is set for DigiCert
 * (revocation); null for Let's Encrypt / manual LE.
 */
@Data
@Builder
@Jacksonized
public class CertIssuanceResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String status;
    private CaProvider caProvider;
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
    private String certSecretHandle;

    /**
     * Versioned Azure Key Vault URI (includes the explicit version segment).
     * Allows the server to pass the exact version to deployment commands so the
     * agent reads the same version it just stored, not whatever "latest" resolves to.
     * Null when the KV backend does not return a version on write.
     */
    private String certSecretHandleWithVersion;

    private String acmeAccountHandle;
    private String respondedAt;

    /** DigiCert order id for revocation / renewal tracking; null when not applicable */
    private String orderId;

    /**
     * What the CA reported it charged for this order, exactly as sent
     * (e.g. {@code "210.00"}). Null when the CA reported none. Optional on the
     * wire: a server that does not know the field ignores it, and it is left out when null so
     * every other CA's message stays as it was.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String caOrderCost;

    /** The currency the CA named for {@link #caOrderCost}; null when it names none (the account's currency). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String caOrderCurrency;

    /**
     * {@code NEW_ORDER} or {@code REPLACEMENT}: a replacement is free inside its order's term and is not
     * billed. Null when the CA does not say, and left out when null.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String caOrderAction;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String keyCustody;
}
