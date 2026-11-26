// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.exception.ConflictException;
import com.certmanagement.exception.CredentialRejectedException;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.exception.LastOrganizationAdminException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.support.common.ApiException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.sql.SQLException;

/**
 * The reason a refused or failed request is recorded with, decided by the exception's type (and, for the
 * exceptions that carry one, their code or HTTP status) only: never by its message, which can quote SQL, a
 * hostname, a vault name or what the caller typed. The same exceptions {@code GlobalExceptionHandler}
 * answers, mapped to the {@link AuditReason} codes the trail renders sentences for; anything else is
 * {@link AuditReason#INTERNAL_ERROR}.
 */
public final class AuditReasons {

    public static final AuditReason PERMISSION_DENIED = AuditReason.of("PERMISSION_DENIED");
    public static final AuditReason NOT_FOUND = AuditReason.of("NOT_FOUND");
    public static final AuditReason INVALID_INPUT = AuditReason.of("INVALID_INPUT");
    public static final AuditReason CONFLICT = AuditReason.of("CONFLICT");
    public static final AuditReason DUPLICATE = AuditReason.of("DUPLICATE");
    public static final AuditReason FEATURE_DISABLED = AuditReason.of("FEATURE_DISABLED");
    public static final AuditReason PAYMENT_REQUIRED = AuditReason.of("PAYMENT_REQUIRED");
    public static final AuditReason RATE_LIMITED = AuditReason.of("RATE_LIMITED");
    public static final AuditReason SERVICE_UNAVAILABLE = AuditReason.of("SERVICE_UNAVAILABLE");
    public static final AuditReason QUERY_TIMEOUT = AuditReason.of("QUERY_TIMEOUT");
    public static final AuditReason LAST_ORGANIZATION_ADMIN = AuditReason.of("LAST_ORGANIZATION_ADMIN");
    public static final AuditReason FEATURE_IN_USE = AuditReason.of("FEATURE_IN_USE");

    /** PostgreSQL's unique_violation: a duplicate, whatever the constraint is called. */
    private static final String UNIQUE_VIOLATION = "23505";

    private AuditReasons() {
    }

    /** The reason {@code failure} is recorded with; {@link AuditReason#INTERNAL_ERROR} for anything unexpected. */
    public static AuditReason of(Throwable failure) {
        if (failure == null) {
            return AuditReason.INTERNAL_ERROR;
        }
        if (failure instanceof AccessDeniedException || failure instanceof ForbiddenException
                || failure instanceof UnauthorizedException || failure instanceof AuthenticationException) {
            return PERMISSION_DENIED;
        }
        if (failure instanceof FeatureDisabledException) {
            return FEATURE_DISABLED;
        }
        if (failure instanceof ResourceNotFoundException || failure instanceof NoResourceFoundException) {
            return NOT_FOUND;
        }
        if (failure instanceof LastOrganizationAdminException) {
            return LAST_ORGANIZATION_ADMIN;
        }
        if (failure instanceof FeatureInUseException) {
            return FEATURE_IN_USE;
        }
        if (failure instanceof DuplicateResourceException) {
            return DUPLICATE;
        }
        if (failure instanceof ConflictException || failure instanceof ObjectOptimisticLockingFailureException) {
            return CONFLICT;
        }
        if (failure instanceof DataIntegrityViolationException) {
            return isUniqueViolation(failure) ? DUPLICATE : AuditReason.INTERNAL_ERROR;
        }
        if (failure instanceof ServiceUnavailableException) {
            return SERVICE_UNAVAILABLE;
        }
        if (failure instanceof org.springframework.dao.QueryTimeoutException
                || failure instanceof jakarta.persistence.QueryTimeoutException) {
            return QUERY_TIMEOUT;
        }
        if (failure instanceof CertExportException export) {
            return AuditReason.of(export.getCode());
        }
        if (failure instanceof CredentialRejectedException rejected) {
            return AuditReason.of(rejected.getCode());
        }
        if (isInvalidInput(failure)) {
            return INVALID_INPUT;
        }
        if (failure instanceof ApiException api) {
            // The support module's codes are stable and code-shaped; only the "already exists" family is read.
            return api.code() != null && api.code().endsWith("_ALREADY_EXISTS") ? DUPLICATE : ofStatus(api.status());
        }
        if (failure instanceof ErrorResponse response) {
            // ResponseStatusException, HandlerMethodValidationException, method-not-allowed and the like.
            return ofStatus(response.getStatusCode().value());
        }
        return AuditReason.INTERNAL_ERROR;
    }

    /** The reason a request answered with {@code status} is recorded with; null for a success (below 400). */
    public static AuditReason ofStatus(int status) {
        if (status < 400) {
            return null;
        }
        return switch (status) {
            case 401, 403 -> PERMISSION_DENIED;
            case 402 -> PAYMENT_REQUIRED;
            case 404, 410 -> NOT_FOUND;
            case 409 -> CONFLICT;
            case 423 -> FEATURE_DISABLED;
            case 429 -> RATE_LIMITED;
            case 503 -> SERVICE_UNAVAILABLE;
            default -> status < 500 ? INVALID_INPUT : AuditReason.INTERNAL_ERROR;
        };
    }

    private static boolean isInvalidInput(Throwable failure) {
        return failure instanceof BindException // MethodArgumentNotValidException is one
                || failure instanceof ConstraintViolationException
                || failure instanceof HttpMessageNotReadableException
                || failure instanceof MethodArgumentTypeMismatchException
                || failure instanceof MissingServletRequestParameterException
                || failure instanceof MissingRequestHeaderException
                || failure instanceof BadRequestException
                || failure instanceof IllegalArgumentException;
    }

    /** Whether a constraint violation is a unique one, from the driver's SQL state (never its message). */
    private static boolean isUniqueViolation(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql && UNIQUE_VIOLATION.equals(sql.getSQLState())) {
                return true;
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return false;
    }
}
