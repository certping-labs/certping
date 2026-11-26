// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.messaging.model.CertIssuanceResponse;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.Optional;

/**
 * The validity dates an issuance or renewal result must carry. A certificate is stored as issued only with a
 * readable expiry date: renewal depends on it, and the agent always sends the leaf's notAfter.
 */
final class IssuedValidity {

    static final String ISSUED_WITHOUT_EXPIRY = "ISSUED_WITHOUT_EXPIRY";

    private IssuedValidity() {
    }

    /** An ISO-8601 date-time with an offset, or an instant; null for anything else. */
    static OffsetDateTime parse(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value.strip());
        } catch (DateTimeParseException notOffsetDateTime) {
            try {
                return Instant.parse(value.strip()).atOffset(ZoneOffset.UTC);
            } catch (DateTimeParseException notInstant) {
                return null;
            }
        }
    }

    /**
     * The failure to record instead of the success, when the result has no readable expiry date. It goes through
     * the agent-error path, so the certificate, its renewal schedule, the reservation, the timeline and the
     * notification end up as for any failed issuance or renewal.
     */
    static Optional<AgentErrorMessage> missingExpiry(CertIssuanceResponse response, boolean renewal) {
        if (parse(response.getValidTo()) != null) {
            return Optional.empty();
        }
        AgentErrorMessage failure = new AgentErrorMessage();
        failure.setRequestId(response.getRequestId());
        failure.setCorrelationId(response.getCorrelationId());
        failure.setOrganizationId(response.getOrganizationId());
        failure.setCertificateXref(response.getCertificateXref());
        failure.setOriginalMessageType(renewal ? "CERT_RENEWAL" : "CERT_ISSUANCE");
        failure.setErrorCode(ISSUED_WITHOUT_EXPIRY);
        failure.setErrorDetail("The issued certificate's expiry date was missing or unreadable: validTo="
                + (response.getValidTo() == null ? "null" : "'" + response.getValidTo() + "'"));
        failure.setRespondedAt(response.getRespondedAt());
        return Optional.of(failure);
    }
}
