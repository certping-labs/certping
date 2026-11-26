// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import com.certmanagement.dto.common.ErrorResponse;
import com.certmanagement.exception.FeatureDisabledException;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.converter.HttpMessageNotReadableException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build());
        request = new MockHttpServletRequest();
        request.setRequestURI("/api/v1/test");
    }

    @Test
    void lockWaitCancelled_mapsTo503WithRetryAfter() {
        var ex = new org.springframework.jdbc.UncategorizedSQLException("PreparedStatementCallback",
                "SELECT pg_advisory_xact_lock(?)",
                new java.sql.SQLException("ERROR: canceling statement due to lock timeout", "55P03"));

        ResponseEntity<ErrorResponse> response = handler.handleDataAccess(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("3");
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getMessage()).contains("retry shortly");
        assertThat(response.getBody().getPath()).isEqualTo("/api/v1/test");
    }

    @Test
    void otherDataAccessFailures_stayUnexpected500() {
        var ex = new org.springframework.jdbc.UncategorizedSQLException("PreparedStatementCallback", "SELECT 1",
                new java.sql.SQLException("connection reset", "08006"));

        ResponseEntity<ErrorResponse> response = handler.handleDataAccess(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNull();
        assertThat(response.getBody().getMessage()).isEqualTo("An unexpected error occurred");
    }

    @Test
    void serviceUnavailable_mapsTo503WithStandardBody() {
        ServiceUnavailableException ex = new ServiceUnavailableException("Message queue unavailable");

        ResponseEntity<ErrorResponse> response = handler.handleServiceUnavailable(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(503);
        assertThat(response.getBody().getError()).isEqualTo("Service Unavailable");
        assertThat(response.getBody().getMessage()).isEqualTo("Message queue unavailable");
        assertThat(response.getBody().getPath()).isEqualTo("/api/v1/test");
    }

    @Test
    void queryTimeout_mapsTo503WithQueryTimeoutCodeAndNoRetryAfter() {
        var ex = new org.springframework.dao.QueryTimeoutException("could not execute query",
                new java.sql.SQLException("ERROR: canceling statement due to statement timeout", "57014"));

        ResponseEntity<Object> response = handler.handleQueryTimeout(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(response.getHeaders().containsHeader(org.springframework.http.HttpHeaders.RETRY_AFTER)).isFalse();
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> body = (java.util.Map<String, Object>) response.getBody();
        assertThat(body).containsOnlyKeys("status", "error", "code", "message", "path", "timestamp")
                .containsEntry("status", 503)
                .containsEntry("error", "Service Unavailable")
                .containsEntry("code", "QUERY_TIMEOUT")
                .containsEntry("path", "/api/v1/test");
        // The SQL and driver message stay in the log, never in the body.
        assertThat((String) body.get("message")).doesNotContain("canceling", "57014");
    }

    @Test
    void jpaQueryTimeout_mapsTo503Too() {
        ResponseEntity<Object> response = handler.handleQueryTimeout(
                new jakarta.persistence.QueryTimeoutException("query timed out"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> body = (java.util.Map<String, Object>) response.getBody();
        assertThat(body).containsEntry("code", "QUERY_TIMEOUT");
    }


    private static List<String> fieldNames(tools.jackson.databind.JsonNode node) {
        List<String> names = new java.util.ArrayList<>();
        node.propertyNames().iterator().forEachRemaining(names::add);
        return names;
    }

    @Test
    void theLastOrganizationAdmin_mapsTo409SayingWhy() {
        ResponseEntity<ErrorResponse> response =
                handler.handleLastOrganizationAdmin(new LastOrganizationAdminException(), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(409);
        assertThat(response.getBody().getError()).isEqualTo("Conflict");
        assertThat(response.getBody().getMessage()).isEqualTo("An organization needs at least one active admin");
        assertThat(response.getBody().getPath()).isEqualTo("/api/v1/test");

        var resolver = new org.springframework.web.method.annotation.ExceptionHandlerMethodResolver(GlobalExceptionHandler.class);
        assertThat(resolver.resolveMethod(new LastOrganizationAdminException()).getName())
                .isEqualTo("handleLastOrganizationAdmin");
    }

    @Test
    void malformedJson_mapsTo400WithStandardBody() {
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("Malformed JSON",
                new org.springframework.mock.http.MockHttpInputMessage(new byte[0]));

        ResponseEntity<ErrorResponse> response = handler.handleHttpMessageNotReadable(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(400);
        assertThat(response.getBody().getError()).isEqualTo("Bad Request");
        assertThat(response.getBody().getMessage()).isEqualTo("Malformed or invalid request body");
    }

    @Test
    void badRequest_preservesFriendlyActionableMessage() {
        BadRequestException ex = new BadRequestException(
                "Namecheap API key secret URL is required. Store the API key in Key Vault, then provide that secret URL.");

        ResponseEntity<ErrorResponse> response = handler.handleBadRequest(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(400);
        assertThat(response.getBody().getError()).isEqualTo("Bad Request");
        assertThat(response.getBody().getMessage())
                .isEqualTo("Namecheap API key secret URL is required. Store the API key in Key Vault, then provide that secret URL.");
        assertThat(response.getBody().getPath()).isEqualTo("/api/v1/test");
    }

    @Test
    void responseStatusException_preservesStatusAndReason() {
        ResponseStatusException ex = new ResponseStatusException(HttpStatus.NOT_FOUND, "Certificate not found");

        ResponseEntity<ErrorResponse> response = handler.handleResponseStatusException(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(404);
        assertThat(response.getBody().getError()).isEqualTo("Not Found");
        assertThat(response.getBody().getMessage()).isEqualTo("Certificate not found");
    }

    @Test
    void featureDisabled_mapsTo423WithFeatureKey() {
        FeatureDisabledException ex = new FeatureDisabledException("PQC_READINESS");

        ResponseEntity<Object> response = handler.handleFeatureDisabled(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.LOCKED);
        assertThat(response.getBody()).isInstanceOf(java.util.Map.class);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> body = (java.util.Map<String, Object>) response.getBody();
        assertThat(body.get("status")).isEqualTo(423);
        assertThat(body.get("code")).isEqualTo("FEATURE_DISABLED");
        assertThat(body.get("feature")).isEqualTo("PQC_READINESS");
    }

    @Test
    void unhandledException_mapsTo500WithoutLeakingInternalDetails() {
        Exception ex = new RuntimeException("DB timeout details should not leak");

        ResponseEntity<ErrorResponse> response = handler.handleGenericException(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(500);
        assertThat(response.getBody().getError()).isEqualTo("Internal Server Error");
        assertThat(response.getBody().getMessage()).isEqualTo("An unexpected error occurred");
    }

    @Test
    void aStaleWriteIsAConflictTheCallerCanRetry() {
        var response = handler.handleStaleWrite(
                new org.springframework.orm.ObjectOptimisticLockingFailureException(
                        com.certmanagement.entity.CertificateEntity.class, 5L),
                request);

        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(response.getBody().getMessage()).contains("changed by another request");
    }
}
