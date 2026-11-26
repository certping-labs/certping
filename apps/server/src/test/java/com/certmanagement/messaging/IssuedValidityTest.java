// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class IssuedValidityTest {

    @Test
    void readsOffsetsAndInstants() {
        assertThat(IssuedValidity.parse("2026-06-12T05:30:00+05:30").toInstant())
                .isEqualTo(Instant.parse("2026-06-12T00:00:00Z"));
        assertThat(IssuedValidity.parse(" 2026-06-12T00:00:00Z ").toInstant())
                .isEqualTo(Instant.parse("2026-06-12T00:00:00Z"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "2026-06-12T00:00:00", "2026-06-12", "1781222400", "garbage"})
    void refusesAnythingWithoutAnOffset(String value) {
        assertThat(IssuedValidity.parse(value)).isNull();
    }

    @Test
    void aResultWithAnExpiryNeedsNoFailure() {
        assertThat(IssuedValidity.missingExpiry(response("2026-06-12T00:00:00Z"), false)).isEmpty();
    }

    @Test
    void aResultWithoutAnExpiryBecomesTheMatchingFailure() {
        AgentErrorMessage issuance = IssuedValidity.missingExpiry(response(null), false).orElseThrow();
        AgentErrorMessage renewal = IssuedValidity.missingExpiry(response("tomorrow"), true).orElseThrow();

        assertThat(issuance.getOriginalMessageType()).isEqualTo("CERT_ISSUANCE");
        assertThat(issuance.getErrorCode()).isEqualTo(IssuedValidity.ISSUED_WITHOUT_EXPIRY);
        assertThat(issuance.getRequestId()).isEqualTo("req-1");
        assertThat(issuance.getCertificateXref()).isEqualTo("cert-1");
        assertThat(issuance.getOrganizationId()).isEqualTo("org-1");
        assertThat(issuance.getErrorDetail()).endsWith("validTo=null");
        assertThat(renewal.getOriginalMessageType()).isEqualTo("CERT_RENEWAL");
        assertThat(renewal.getErrorDetail()).endsWith("validTo='tomorrow'");
    }

    private static CertIssuanceResponse response(String validTo) {
        CertIssuanceResponse response = new CertIssuanceResponse();
        response.setRequestId("req-1");
        response.setCorrelationId("corr-1");
        response.setOrganizationId("org-1");
        response.setCertificateXref("cert-1");
        response.setValidTo(validTo);
        return response;
    }
}
