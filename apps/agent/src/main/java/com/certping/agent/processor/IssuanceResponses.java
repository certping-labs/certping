// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertIssuanceResponse;
import com.certping.agent.ssl.IssuanceResult;

import java.time.Clock;
import java.time.OffsetDateTime;

/** Builds the {@code CERT_ISSUANCE_RESPONSE} for an issued, renewed or manually validated certificate. */
final class IssuanceResponses {

    static final String ISSUED = "ISSUED";
    static final String RENEWED = "RENEWED";

    private IssuanceResponses() {
    }

    /**
     * The result the server records for {@code certificateXref}, answering the command identified by
     * {@code requestId} and {@code correlationId}.
     */
    static CertIssuanceResponse of(String requestId, String correlationId, String organizationId,
                                   String certificateXref, String status, CaProvider caProvider,
                                   IssuanceResult result, Clock clock) {
        return CertIssuanceResponse.builder()
                .requestId(requestId)
                .correlationId(correlationId)
                .organizationId(organizationId)
                .certificateXref(certificateXref)
                .status(status)
                .caProvider(caProvider)
                .certSecretHandle(result.certSecretHandle())
                .certSecretHandleWithVersion(result.certSecretHandleWithVersion())
                .acmeAccountHandle(result.acmeAccountHandle())
                .issuer(result.issuer())
                .serialNumber(result.serial())
                .fingerprintSha256(result.fingerprint())
                .validFrom(result.validFrom() != null ? result.validFrom().toString() : null)
                .validTo(result.validTo() != null ? result.validTo().toString() : null)
                .signatureAlgorithm(result.signatureAlgorithm())
                .signatureAlgorithmOid(result.signatureAlgorithmOid())
                .subjectDn(result.subjectDn())
                .commonName(result.commonName())
                .publicKeyAlgorithm(result.publicKeyAlgorithm())
                .keySize(result.keySize())
                .publicKeyCurve(result.publicKeyCurve())
                .keyUsage(result.keyUsage())
                .extendedKeyUsage(result.extendedKeyUsage())
                .subjectKeyIdentifier(result.subjectKeyIdentifier())
                .authorityKeyIdentifier(result.authorityKeyIdentifier())
                .certType(result.certType())
                .orderId(result.orderId())
                .caOrderCost(result.caOrderCostAmount())
                .caOrderCurrency(result.caOrderCostCurrency())
                .caOrderAction(result.caOrderAction() == null ? null : result.caOrderAction().name())
                .keyCustody(result.keyCustody() == null ? null : result.keyCustody().name())
                .respondedAt(OffsetDateTime.now(clock).toString())
                .build();
    }
}
