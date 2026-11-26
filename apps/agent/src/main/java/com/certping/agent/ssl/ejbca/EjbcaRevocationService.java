// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Locale;

/** Idempotent EJBCA leaf-certificate revocation with post-write confirmation. */
@Service
@RequiredArgsConstructor
public class EjbcaRevocationService {
    private final EjbcaClient client;

    public Result revoke(String issuerDn, String serialNumber, String reasonValue) {
        Reason reason = parseReason(reasonValue);
        Status before = status(issuerDn, serialNumber);
        if (before.revoked()) {
            return new Result(true, before.reason(), before.observedAt());
        }
        try {
            client.revoke(issuerDn, serialNumber, reason.name());
        } catch (AgentException revokeFailure) {
            Status reconciled = reconcileAfterFailedWrite(issuerDn, serialNumber, revokeFailure);
            if (reconciled.revoked()) {
                return new Result(true, reconciled.reason(), reconciled.observedAt());
            }
            throw revokeFailure;
        }
        Status after = status(issuerDn, serialNumber);
        if (!after.revoked()) {
            throw new TransientAgentException("EJBCA_REVOCATION_NOT_CONFIRMED",
                    "EJBCA accepted the revoke request but still reports the certificate as active");
        }
        return new Result(false, after.reason(), after.observedAt());
    }

    public Status status(String issuerDn, String serialNumber) {
        JsonNode response = client.revocationStatus(issuerDn, serialNumber);
        if (response == null || !response.isObject()
                || !response.path("revoked").isBoolean()) {
            throw invalidStatus("EJBCA returned no boolean revoked field");
        }
        String observedIssuer = requiredText(response, "issuer_dn");
        String observedSerial = requiredText(response, "serial_number");
        if (!sameIssuer(issuerDn, observedIssuer) || !sameSerial(serialNumber, observedSerial)) {
            throw invalidStatus("EJBCA returned status for a different certificate");
        }
        boolean revoked = response.path("revoked").booleanValue();
        String reason = text(response, "revocation_reason");
        if (reason == null) reason = text(response, "reason");
        String date = text(response, "revocation_date");
        return new Status(revoked, reason, date == null ? Instant.now().toString() : date);
    }

    private Status reconcileAfterFailedWrite(
            String issuerDn, String serialNumber, AgentException revokeFailure) {
        try {
            return status(issuerDn, serialNumber);
        } catch (AgentException statusFailure) {
            statusFailure.addSuppressed(revokeFailure);
            throw statusFailure;
        }
    }

    private static String requiredText(JsonNode response, String field) {
        String value = text(response, field);
        if (value == null) {
            throw invalidStatus("EJBCA returned no " + field + " field");
        }
        return value;
    }

    private static boolean sameIssuer(String expected, String observed) {
        try {
            return new X500Principal(expected).equals(new X500Principal(observed));
        } catch (IllegalArgumentException exception) {
            throw invalidStatus("EJBCA returned an invalid issuer DN");
        }
    }

    private static boolean sameSerial(String expected, String observed) {
        try {
            return serial(expected).equals(serial(observed));
        } catch (NumberFormatException exception) {
            throw invalidStatus("EJBCA returned an invalid certificate serial number");
        }
    }

    private static BigInteger serial(String value) {
        String normalized = value == null ? "" : value.trim().replace(":", "");
        if (normalized.regionMatches(true, 0, "0x", 0, 2)) {
            normalized = normalized.substring(2);
        }
        if (normalized.isEmpty()) {
            throw new NumberFormatException("empty serial");
        }
        return new BigInteger(normalized, 16);
    }

    private static TransientAgentException invalidStatus(String message) {
        return new TransientAgentException("EJBCA_REVOCATION_STATUS_INVALID", message);
    }

    private static Reason parseReason(String value) {
        try {
            Reason reason = Reason.valueOf(value == null ? "" : value.trim().toUpperCase(Locale.ROOT));
            if (!SAFE_REASONS.contains(reason)) throw new IllegalArgumentException();
            return reason;
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException("EJBCA_REVOCATION_REASON_UNSUPPORTED",
                    "Unsupported EJBCA leaf-certificate revocation reason: " + value);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() || value.asString().isBlank() ? null : value.asString();
    }

    private static final EnumSet<Reason> SAFE_REASONS = EnumSet.of(
            Reason.UNSPECIFIED, Reason.KEY_COMPROMISE, Reason.AFFILIATION_CHANGED,
            Reason.SUPERSEDED, Reason.CESSATION_OF_OPERATION, Reason.PRIVILEGES_WITHDRAWN);

    private enum Reason {
        UNSPECIFIED,
        KEY_COMPROMISE,
        AFFILIATION_CHANGED,
        SUPERSEDED,
        CESSATION_OF_OPERATION,
        PRIVILEGES_WITHDRAWN
    }

    public record Status(boolean revoked, String reason, String observedAt) {}
    public record Result(boolean alreadyRevoked, String reason, String observedAt) {}
}
