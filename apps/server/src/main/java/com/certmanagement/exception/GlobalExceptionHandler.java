// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import com.certmanagement.audit.AuditFailures;
import com.certmanagement.dto.common.ErrorResponse;
import com.certmanagement.interceptor.RequestContextInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import com.certmanagement.support.common.ApiException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.LinkedHashMap;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import com.certmanagement.utils.RequestContextLogger;
import org.slf4j.Logger;

/**
 * Global exception handler for REST API.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private static final int LOCK_WAIT_RETRY_AFTER_SECONDS = 3;

    private final ObjectMapper objectMapper;
    /**
     * Records the refusal of a request the handler method never saw (a {@code @Valid} body, an unreadable
     * body, a bad parameter) as the failure its {@code @AuditFailure} declares; null where no audit
     * trail is wired, as in standalone controller tests.
     */
    private final AuditFailures auditFailures;

    public GlobalExceptionHandler(ObjectMapper objectMapper) {
        this(objectMapper, (AuditFailures) null);
    }

    public GlobalExceptionHandler(ObjectMapper objectMapper, AuditFailures auditFailures) {
        this.objectMapper = objectMapper;
        this.auditFailures = auditFailures;
    }

    /** The advice as Spring builds it; a context without the audit trail (a web slice test) records nothing. */
    @Autowired
    public GlobalExceptionHandler(ObjectMapper objectMapper, ObjectProvider<AuditFailures> auditFailures) {
        this(objectMapper, auditFailures.getIfAvailable());
    }

    private static final String REDACTED_VALUE = "[REDACTED]";
    private static final Set<String> SENSITIVE_FIELD_NAMES = Set.of(
            "authcode", "password", "confirmpassword", "currentpassword",
            "newpassword", "secret", "apikey", "token");

    @ExceptionHandler(FeatureDisabledException.class)
    public ResponseEntity<Object> handleFeatureDisabled(
            FeatureDisabledException ex, HttpServletRequest request) {
        var body = new LinkedHashMap<String, Object>();
        body.put("status", 423);
        body.put("error", "Feature Disabled");
        body.put("code", ex.getCode());
        body.put("feature", ex.getFeatureKey());
        body.put("message", ex.getMessage());
        body.put("path", request.getRequestURI());
        body.put("timestamp", java.time.Instant.now());
        return ResponseEntity.status(423).body(body);
    }

    @ExceptionHandler(CertExportException.class)
    public ResponseEntity<Object> handleCertExport(CertExportException ex, HttpServletRequest request) {
        return certExportErrorResponse(ex, request);
    }

    /**
     * The certificate-export error envelope: status, error, code, optional reason, message, path and
     * timestamp, plus {@code Retry-After} when set. Shared with the export controller's own handlers
     * so every export error has the same shape.
     */
    public static ResponseEntity<Object> certExportErrorResponse(CertExportException ex, HttpServletRequest request) {
        HttpStatus status = ex.getStatus();
        var body = new LinkedHashMap<String, Object>();
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("code", ex.getCode());
        if (ex.getReason() != null) {
            body.put("reason", ex.getReason());
        }
        body.put("message", ex.getMessage());
        body.put("path", request.getRequestURI());
        body.put("timestamp", Instant.now());
        ResponseEntity.BodyBuilder response = ResponseEntity.status(status);
        if (ex.getRetryAfterSeconds() != null) {
            response.header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()));
        }
        return response.body(body);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(
            ResourceNotFoundException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateResource(
            DuplicateResourceException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict(ConflictException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(LastOrganizationAdminException.class)
    public ResponseEntity<ErrorResponse> handleLastOrganizationAdmin(
            LastOrganizationAdminException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    /** The body lists what keeps the feature in use, in the shape of the disable-check blockers. */
    @ExceptionHandler(FeatureInUseException.class)
    public ResponseEntity<Object> handleFeatureInUse(FeatureInUseException ex, HttpServletRequest request) {
        var body = new LinkedHashMap<String, Object>();
        body.put("status", HttpStatus.CONFLICT.value());
        body.put("error", HttpStatus.CONFLICT.getReasonPhrase());
        body.put("code", FeatureInUseException.CODE);
        body.put("featureKey", ex.getFeatureKey());
        body.put("blockers", ex.getBlockers());
        body.put("message", ex.getMessage());
        body.put("path", request.getRequestURI());
        body.put("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    /** The body names the feature, so the page can show it as managed by CertPing. */
    @ExceptionHandler(ManagedByCertpingException.class)
    public ResponseEntity<Object> handleManagedByCertping(ManagedByCertpingException ex, HttpServletRequest request) {
        var body = new LinkedHashMap<String, Object>();
        body.put("status", HttpStatus.FORBIDDEN.value());
        body.put("error", HttpStatus.FORBIDDEN.getReasonPhrase());
        body.put("code", ManagedByCertpingException.CODE);
        body.put("featureKey", ex.getFeatureKey());
        body.put("message", ex.getMessage());
        body.put("path", request.getRequestURI());
        body.put("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    /** The body carries the bounds, so the settings card can say what it accepts. */
    @ExceptionHandler(AuditRetentionOutOfRangeException.class)
    public ResponseEntity<Object> handleAuditRetentionOutOfRange(
            AuditRetentionOutOfRangeException ex, HttpServletRequest request) {
        var body = new LinkedHashMap<String, Object>();
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
        body.put("code", AuditRetentionOutOfRangeException.CODE);
        body.put("message", ex.getMessage());
        body.put("minMonths", ex.getMinMonths());
        body.put("maxMonths", ex.getMaxMonths());
        body.put("path", request.getRequestURI());
        body.put("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /** A write from a copy that another request changed in the meantime; the caller should reload. */
    @ExceptionHandler(org.springframework.orm.ObjectOptimisticLockingFailureException.class)
    public ResponseEntity<ErrorResponse> handleStaleWrite(
            org.springframework.orm.ObjectOptimisticLockingFailureException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.CONFLICT,
                "This record was changed by another request. Reload it and try again.", request);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(
            UnauthorizedException ex, HttpServletRequest request) {
        contextLogger().warn("Unauthorized access attempt [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<ErrorResponse> handleForbidden(
            ForbiddenException ex, HttpServletRequest request) {
        contextLogger().warn("Forbidden access attempt [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(
            BadRequestException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    /**
     * A query cancelled by its timeout (PostgreSQL statement_timeout or a JDBC query timeout). No
     * Retry-After: the same query would take as long again, so the caller should narrow it instead.
     * The repository proxy translates the JPA exception to Spring's; the JPA one reaches here from
     * code that runs queries outside a repository.
     */
    @ExceptionHandler({org.springframework.dao.QueryTimeoutException.class,
            jakarta.persistence.QueryTimeoutException.class})
    public ResponseEntity<Object> handleQueryTimeout(RuntimeException ex, HttpServletRequest request) {
        contextLogger().warn("Query timed out [{}] path={} sqlState={}",
                RequestContextInterceptor.getFormattedContext(), request.getRequestURI(), sqlStateOf(ex));
        var body = new LinkedHashMap<String, Object>();
        body.put("status", HttpStatus.SERVICE_UNAVAILABLE.value());
        body.put("error", HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase());
        body.put("code", "QUERY_TIMEOUT");
        body.put("message", "The request took too long to complete. Narrow it, for example with filters"
                + " or a shorter date range, and try again.");
        body.put("path", request.getRequestURI());
        body.put("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /**
     * An audit export refused before any row was read: too large (400), the hourly limit (429, with
     * {@code Retry-After}), or its own audit row not written (503). The code is stable for the page to branch on.
     */
    @ExceptionHandler(AuditExportRefusedException.class)
    public ResponseEntity<Object> handleAuditExportRefused(AuditExportRefusedException ex, HttpServletRequest request) {
        var body = new LinkedHashMap<String, Object>();
        body.put("status", ex.getStatus().value());
        body.put("error", ex.getStatus().getReasonPhrase());
        body.put("code", ex.getCode());
        body.put("message", ex.getMessage());
        if (ex.getMaxRows() != null) {
            body.put("maxRows", ex.getMaxRows());
        }
        body.put("path", request.getRequestURI());
        body.put("timestamp", Instant.now());
        // JSON whatever the export asked for (Accept: text/csv): a preset content type is not negotiated.
        ResponseEntity.BodyBuilder response = ResponseEntity.status(ex.getStatus())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON);
        if (ex.getRetryAfterSeconds() != null) {
            response.header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()));
        }
        return response.body(body);
    }

    private static String sqlStateOf(Throwable ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof java.sql.SQLException sqlException) {
                return sqlException.getSQLState();
            }
        }
        return null;
    }

    @ExceptionHandler(ServiceUnavailableException.class)
    public ResponseEntity<ErrorResponse> handleServiceUnavailable(
            ServiceUnavailableException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage(), request);
    }

    @ExceptionHandler(SsoAuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleSsoAuthenticationException(
            SsoAuthenticationException ex, HttpServletRequest request) {
        contextLogger().error("SSO authentication error [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    @ExceptionHandler(SsoValidationException.class)
    public ResponseEntity<ErrorResponse> handleSsoValidationException(
            SsoValidationException ex, HttpServletRequest request) {
        contextLogger().error("SSO validation error [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request) {
        contextLogger().warn("Authentication failed [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Authentication required", request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {
        contextLogger().warn("Access denied [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.FORBIDDEN, "Insufficient permissions", request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        BindingResult result = ex.getBindingResult();

        List<ErrorResponse.FieldError> fieldErrors = result.getFieldErrors().stream()
            .map(error -> ErrorResponse.FieldError.builder()
                .field(error.getField())
                .message(error.getDefaultMessage())
                .rejectedValue(safeRejectedValue(error.getField(), error.getRejectedValue()))
                .build())
            .collect(Collectors.toList());

        ErrorResponse response = ErrorResponse.builder()
            .status(HttpStatus.BAD_REQUEST.value())
            .error("Validation Failed")
            .message("Request validation failed")
            .path(request.getRequestURI())
            .timestamp(Instant.now())
            .fieldErrors(fieldErrors)
            .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    /**
     * An {@link IllegalArgumentException} can come from anywhere (a parser, a library, an enum lookup) and
     * its message may name internals, so the caller gets a generic 400 and the detail goes to the log.
     * Messages meant for the caller are thrown as {@link BadRequestException} or another of the app's own
     * types, which have their own handlers.
     */
    static final String INVALID_REQUEST_MESSAGE = "The request is invalid";

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest request) {
        contextLogger().warn("Invalid argument [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        return buildErrorResponse(HttpStatus.BAD_REQUEST, INVALID_REQUEST_MESSAGE, request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        String message = "Invalid value for parameter '" + ex.getName() + "'";
        return buildErrorResponse(HttpStatus.BAD_REQUEST, message, request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        return buildErrorResponse(HttpStatus.BAD_REQUEST,
                "Malformed or invalid request body", request);
    }

    /**
     * Race-condition safety net for unique-constraint violations that slipped past service-layer
     * pre-checks (e.g. two parallel POSTs creating the same email). Maps the most common index
     * names to friendly 409 messages; falls back to a generic conflict message otherwise.
     *
     * <p>This is intentionally LAST-RESORT — services should pre-check unique constraints and
     * throw {@link DuplicateResourceException} for clean, deterministic 409s. This handler
     * catches the leftover race-condition window.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityViolation(
            DataIntegrityViolationException ex, HttpServletRequest request) {
        String root = ex.getMostSpecificCause() != null
                ? String.valueOf(ex.getMostSpecificCause().getMessage())
                : "";
        String friendly;
        if (root.contains("uk_users_email_global")) {
            friendly = "A user with this email already exists.";
        } else if (root.contains("uk_users_username")) {
            friendly = "A user with this username already exists.";
        } else if (root.contains("duplicate key value")) {
            friendly = "This record already exists.";
        } else {
            friendly = "The request conflicts with the current state of the resource.";
        }
        // Don't echo the raw SQL/exception message — it leaks index names and PII.
        contextLogger().warn("DB constraint violation [{}]: {}",
                RequestContextInterceptor.getFormattedContext(), root);
        return buildErrorResponse(HttpStatus.CONFLICT, friendly, request);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingServletRequestParameter(
            MissingServletRequestParameterException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        String message = "Missing required query parameter '" + ex.getParameterName() + "'";
        return buildErrorResponse(HttpStatus.BAD_REQUEST, message, request);
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ErrorResponse> handleMissingRequestHeader(
            MissingRequestHeaderException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        String message = "Missing required header '" + ex.getHeaderName() + "'";
        return buildErrorResponse(HttpStatus.BAD_REQUEST, message, request);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(
            ConstraintViolationException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        List<ErrorResponse.FieldError> fieldErrors = ex.getConstraintViolations().stream()
                .map(this::toFieldError)
                .collect(Collectors.toList());

        ErrorResponse response = ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Failed")
                .message("Request validation failed")
                .path(request.getRequestURI())
                .timestamp(Instant.now())
                .fieldErrors(fieldErrors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ErrorResponse> handleResponseStatusException(
            ResponseStatusException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
        String message = ex.getReason() != null ? ex.getReason() : status.getReasonPhrase();
        // Keeps headers the exception carries, such as the agent gateway's Retry-After on a 429.
        HttpHeaders headers = new HttpHeaders();
        headers.addAll(ex.getHeaders());
        return buildErrorResponse(status, message, request, headers);
    }

    @ExceptionHandler(ErrorResponseException.class)
    public ResponseEntity<ErrorResponse> handleErrorResponseException(
            ErrorResponseException ex, HttpServletRequest request) {
        auditRefusedRequest(request, ex);
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
        String message = ex.getBody() != null && ex.getBody().getDetail() != null
                ? ex.getBody().getDetail()
                : status.getReasonPhrase();
        return buildErrorResponse(status, message, request);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.METHOD_NOT_ALLOWED, "Request method not supported", request,
                ex.getHeaders());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFound(
            NoResourceFoundException ex, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.NOT_FOUND, "Resource not found", request);
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleSupportApiException(
            ApiException ex,
            HttpServletRequest request) {
        HttpStatus status = HttpStatus.resolve(ex.status());
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        contextLogger().warn("Support module failure code={} status={} message='{}'",
                ex.code(), ex.status(), ex.getMessage());
        return buildErrorResponse(status, ex.getMessage(), request);
    }

    /** A lock wait cancelled by {@code lock_timeout}: the caller is told to retry, not that something broke. */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleDataAccess(DataAccessException ex, HttpServletRequest request) {
        if (!SqlStates.isLockNotAvailable(ex)) {
            return handleGenericException(ex, request);
        }
        contextLogger().warn("Lock wait cancelled [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage());
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(LOCK_WAIT_RETRY_AFTER_SECONDS));
        return buildErrorResponse(HttpStatus.SERVICE_UNAVAILABLE,
                "Another request of this organization is being processed; retry shortly", request, headers);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex, HttpServletRequest request) {
        contextLogger().error("Unexpected error [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage(), ex);
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
            "An unexpected error occurred", request);
    }

    @ExceptionHandler(Throwable.class)
    public ResponseEntity<ErrorResponse> handleThrowable(
            Throwable ex, HttpServletRequest request) {
        contextLogger().error("Unhandled throwable [{}]: {}", RequestContextInterceptor.getFormattedContext(), ex.getMessage(), ex);
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
            "An unexpected error occurred", request);
    }

    /**
     * A request refused while its handler method's arguments were resolved: the aspect that records
     * {@code @AuditFailure} never ran, so the failure is recorded from here, from the handler method the
     * request was mapped to. A failure the aspect already recorded is not recorded again.
     */
    private void auditRefusedRequest(HttpServletRequest request, Throwable refusal) {
        if (auditFailures != null) {
            auditFailures.recordRefusedRequest(request, refusal);
        }
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse(
            HttpStatus status, String message, HttpServletRequest request) {
        return buildErrorResponse(status, message, request, new HttpHeaders());
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse(
            HttpStatus status, String message, HttpServletRequest request, HttpHeaders headers) {
        ErrorResponse response = ErrorResponse.builder()
            .status(status.value())
            .error(status.getReasonPhrase())
            .message(message)
            .path(request.getRequestURI())
            .timestamp(Instant.now())
            .build();
        return ResponseEntity.status(status).headers(headers).body(response);
    }

    private ErrorResponse.FieldError toFieldError(ConstraintViolation<?> violation) {
        String field = violation.getPropertyPath() != null
                ? violation.getPropertyPath().toString()
                : "request";
        return ErrorResponse.FieldError.builder()
                .field(field)
                .message(violation.getMessage())
                .rejectedValue(safeRejectedValue(field, violation.getInvalidValue()))
                .build();
    }

    private Object safeRejectedValue(String field, Object rejectedValue) {
        if (field == null) {
            return rejectedValue;
        }
        String normalizedField = field.replaceAll("[^A-Za-z]", "").toLowerCase(Locale.ROOT);
        return SENSITIVE_FIELD_NAMES.stream().anyMatch(normalizedField::endsWith)
                ? REDACTED_VALUE
                : rejectedValue;
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(GlobalExceptionHandler.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
