// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.DuplicateResourceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

@Slf4j
@Component
public class CertificateStatusValidator {

    /**
     * Central certificate operations used by service entry points.
     */
    public enum CertOperation {
        ISSUE_AUTOMATED,
        ISSUE_MANUAL_TXT_RECORD_GEN,
        ISSUE_MANUAL_VALIDATE_DNS,
        RENEW_MANUAL,
        RENEW_SCHEDULER,
        DEPLOY,
        REVOKE,
        DELETE,
        MANUAL_DNS_VALIDATE,
        CONVERT_TO_AUTOMATED
    }

    private static final Set<CertificateStatus> ALL_STATUSES =
        Collections.unmodifiableSet(EnumSet.allOf(CertificateStatus.class));

    private static final Set<CertificateStatus> RENEWABLE_STATUSES =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.ACTIVE,
            CertificateStatus.EXPIRED));

    private static final Set<CertificateStatus> MANUAL_DNS_VALIDATE_STATUSES =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.AWAITING_DNS,
            CertificateStatus.FAILED));

    private static final Set<CertificateStatus> DEPLOYABLE_STATUSES =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.ACTIVE,
            CertificateStatus.RENEWING,
            CertificateStatus.RENEW_SUCCESS));

    private static final Set<CertificateStatus> REVOCABLE_STATUSES =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.ACTIVE,
            CertificateStatus.REVOCATION_FAILED,
            CertificateStatus.REVOKING,
            CertificateStatus.REVOKED));

    private static final Set<CertificateStatus> DELETABLE_STATUSES =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.PENDING,
            CertificateStatus.PENDING_DNS,
            CertificateStatus.AWAITING_DNS,
            CertificateStatus.FAILED,
            CertificateStatus.REVOKED,
            CertificateStatus.EXPIRED));

    private static final Set<CertificateStatus> CONVERT_ACTIVE_OR_EXPIRED =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.ACTIVE,
            CertificateStatus.EXPIRED));

    private static final Set<CertificateStatus> CONVERT_TERMINAL_REISSUE =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.FAILED,
            CertificateStatus.REVOKED,
            CertificateStatus.REVOCATION_FAILED));

    private static final Set<CertificateStatus> CONVERT_IN_PROGRESS_AUTOMATED =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.PENDING,
            CertificateStatus.RENEWING));

    private static final Set<CertificateStatus> CONVERT_MANUAL_IN_FLIGHT =
        Collections.unmodifiableSet(EnumSet.of(
            CertificateStatus.PENDING_DNS,
            CertificateStatus.AWAITING_DNS,
            CertificateStatus.VALIDATING));

    private static final Set<CertificateStatus> CONVERT_ALLOWED_STATUSES;

    static {
    EnumSet<CertificateStatus> combined = EnumSet.noneOf(CertificateStatus.class);
        combined.addAll(CONVERT_ACTIVE_OR_EXPIRED);
        combined.addAll(CONVERT_TERMINAL_REISSUE);
        combined.addAll(CONVERT_IN_PROGRESS_AUTOMATED);
        combined.addAll(CONVERT_MANUAL_IN_FLIGHT);
        CONVERT_ALLOWED_STATUSES = Collections.unmodifiableSet(combined);
    }

    public Set<CertificateStatus> allowedStatusesFor(CertOperation operation) {
        return switch (operation) {
            case ISSUE_AUTOMATED,
                  ISSUE_MANUAL_TXT_RECORD_GEN -> ALL_STATUSES;

            case DELETE -> DELETABLE_STATUSES;

            case ISSUE_MANUAL_VALIDATE_DNS,
                 MANUAL_DNS_VALIDATE -> MANUAL_DNS_VALIDATE_STATUSES;

            case RENEW_MANUAL,
                 RENEW_SCHEDULER -> RENEWABLE_STATUSES;

            case DEPLOY -> DEPLOYABLE_STATUSES;
            case REVOKE -> REVOCABLE_STATUSES;
            case CONVERT_TO_AUTOMATED -> CONVERT_ALLOWED_STATUSES;
        };
    }

    public boolean isAllowedForOperation(String status, CertOperation operation) {
        if (status == null || status.isBlank()) {
            return false;
        }
        try {
            return allowedStatusesFor(operation).contains(CertificateStatus.valueOf(status));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public boolean isAllowedForOperation(CertificateStatus status, CertOperation operation) {
        return status != null && allowedStatusesFor(operation).contains(status);
    }

    public boolean isAllowedForOperation(CertificateEntity cert, CertOperation operation) {
        return cert != null && isAllowedForOperation(cert.getStatus(), operation);
    }

    public void validateForOperation(CertificateEntity cert, String xref, CertOperation operation) {
        String status = cert != null ? cert.getStatus() : null;
        if (isAllowedForOperation(status, operation)) {
            return;
        }

        throw new BadRequestException(
                "Certificate '" + xref + "' cannot perform operation " + operation
                        + " in current state: " + status
                        + ". Allowed: " + allowedStatusesFor(operation));
    }

    public boolean isConversionStatusActiveOrExpired(String status) {
        return isAllowedForOperation(status, CertOperation.CONVERT_TO_AUTOMATED)
                && isAllowedForOperation(status, CertOperation.RENEW_MANUAL);
    }

    public boolean isConversionStatusTerminalReissue(String status) {
        if (status == null || status.isBlank()) {
            return false;
        }
        try {
            return CONVERT_TERMINAL_REISSUE.contains(CertificateStatus.valueOf(status));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public boolean isConversionStatusInProgressAutomated(String status) {
        if (status == null || status.isBlank()) {
            return false;
        }
        try {
            return CONVERT_IN_PROGRESS_AUTOMATED.contains(CertificateStatus.valueOf(status));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public boolean isConversionStatusManualInFlight(String status) {
        if (status == null || status.isBlank()) {
            return false;
        }
        try {
            return CONVERT_MANUAL_IN_FLIGHT.contains(CertificateStatus.valueOf(status));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public boolean isIdempotentNoOp(String status, CertOperation operation) {
        if (status == null || status.isBlank()) {
            return false;
        }

        return switch (operation) {
            case REVOKE -> CertificateStatus.REVOKING.name().equals(status)
                    || CertificateStatus.REVOKED.name().equals(status);
            default -> false;
        };
    }

    public void validateForManualRenewal(CertificateEntity cert, String xref) {
        if (cert.getDeletedAt() != null) {
            throw new BadRequestException(
                    "Certificate '" + xref + "' has been deleted and cannot be renewed. Re-issue the certificate instead.");
        }

        String status = cert.getStatus();
        if (isAllowedForOperation(status, CertOperation.RENEW_MANUAL)) {
            if (CertificateStatus.RENEWING.name().equals(status)) {
                log.warn("[CertificateStatusValidator] Manual renewal requested for cert={} already in {} state - forcing re-dispatch.",
                        xref, CertificateStatus.RENEWING.name());
            }
            return;
        }

        if (CertificateStatus.PENDING.name().equals(status)) {
            throw new DuplicateResourceException(
                    "Certificate '" + xref + "' has an issuance in progress (status=" + CertificateStatus.PENDING.name() + ").");
        }
        if (CertificateStatus.REVOKED.name().equals(status)) {
            throw new BadRequestException(
                    "Certificate '" + xref + "' has been revoked and cannot be renewed. Re-issue the certificate instead.");
        }
        if (CertificateStatus.REVOCATION_FAILED.name().equals(status)) {
            throw new BadRequestException(
                    "Certificate '" + xref + "' is in " + CertificateStatus.REVOCATION_FAILED.name() + " state. Resolve revocation first.");
        }

        throw new BadRequestException(
                "Certificate '" + xref + "' cannot be renewed in current state: " + status
                        + ". Allowed: " + allowedStatusesFor(CertOperation.RENEW_MANUAL));
    }

    public boolean isEligibleForScheduledRenewal(CertificateEntity cert, String xref) {
        if (cert.getDeletedAt() != null) {
            log.debug("[CertificateStatusValidator] Skipping scheduled renewal xref={}: soft-deleted", xref);
            return false;
        }

        String status = cert.getStatus();
        boolean eligible = isAllowedForOperation(status, CertOperation.RENEW_SCHEDULER);

        if (!eligible) {
            log.debug("[CertificateStatusValidator] Skipping scheduled renewal xref={}: status={} not eligible (allowed: {})",
                    xref, status, allowedStatusesFor(CertOperation.RENEW_SCHEDULER));
        }
        return eligible;
    }
}
