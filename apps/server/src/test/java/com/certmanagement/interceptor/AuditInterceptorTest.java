// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.constants.ActionType;
import com.certmanagement.security.GatewayRequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/** Unit tests for {@link AuditInterceptor}: one internal api.request row per mutating request. */
@ExtendWith(MockitoExtension.class)
class AuditInterceptorTest {

    @Mock private AuditRecorder recorder;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;

    private AuditInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new AuditInterceptor(recorder);
        GatewayRequestContext.clear();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
        interceptor.afterCompletion(request, response, new Object(), null);
    }

    @Test
    void aMutatingRequestLogsItsRouteStatusAndDuration() {
        Logger logger = (Logger) LoggerFactory.getLogger(AuditInterceptor.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
        try {
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/api/v1/certs/issue");
            when(request.getAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingPattern"))
                    .thenReturn("/api/v1/certs/issue");
            when(response.getStatus()).thenReturn(202);

            interceptor.preHandle(request, response, new Object());
            interceptor.afterCompletion(request, response, new Object(), null);

            assertThat(logs.list).extracting(ILoggingEvent::getFormattedMessage)
                    .anySatisfy(line -> assertThat(line)
                            .startsWith("request finished method=POST route=/api/v1/certs/issue status=202 durationMs=")
                            .doesNotContain("?"));
        } finally {
            logger.detachAppender(logs);
        }
    }

    private AuditEventRow captureRow() {
        ArgumentCaptor<AuditEventRow> cap = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordAsync(cap.capture());
        return cap.getValue();
    }

    @Test
    void aPostIsRecordedAsAnInternalRequestRowWithTheCallerCapturedBeforeTheContextClears() {
        GatewayRequestContext.set(7, "100", "req-1", "jane@acme.test");
        when(request.getRequestURI()).thenReturn("/api/v1/certs/list");
        when(request.getMethod()).thenReturn("POST");
        when(response.getStatus()).thenReturn(201);

        RequestContextInterceptor.setCurrentClientIp("203.0.113.5");

        assertThat(interceptor.preHandle(request, response, new Object())).isTrue();
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
        interceptor.afterCompletion(request, response, new Object(), null);

        AuditEventRow row = captureRow();
        assertThat(row.event()).isEqualTo("api.request");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.actorType()).isEqualTo(AuditActorType.USER);
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.organizationId()).isEqualTo(100L);
        assertThat(row.action()).isEqualTo(ActionType.API_CREATE.name());
        assertThat(row.resourceType()).isEqualTo("CERTIFICATE");
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(row.ipAddress()).isEqualTo("203.0.113.5");
        assertThat(row.details().attributes()).containsEntry("method", "POST").containsEntry("status", "201")
                .containsKey("durationMs").doesNotContainKey("route");
        assertThat(row.summary()).doesNotContain("jane@acme.test");
    }

    @Test
    void aFailedRequestIsAFailureRowWithTheStatusReasonNeverTheExceptionMessage() {
        when(request.getRequestURI()).thenReturn("/api/v1/users/5");
        when(request.getMethod()).thenReturn("DELETE");
        when(response.getStatus()).thenReturn(500);

        interceptor.preHandle(request, response, new Object());
        interceptor.afterCompletion(request, response, new Object(), new RuntimeException("boom"));

        AuditEventRow row = captureRow();
        assertThat(row.action()).isEqualTo(ActionType.API_DELETE.name());
        assertThat(row.resourceType()).isEqualTo("USER");
        assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(row.errorCode()).isEqualTo("INTERNAL_ERROR");
        assertThat(row.summary()).doesNotContain("boom");
    }

    @Test
    void invalidOrganizationIdLeavesOrgNullButStillRecords() {
        GatewayRequestContext.set(3, "not-a-number", "req-2", "bob@acme.test");
        when(request.getRequestURI()).thenReturn("/api/v1/some/thing");
        when(request.getMethod()).thenReturn("PUT");
        when(response.getStatus()).thenReturn(200);

        interceptor.preHandle(request, response, new Object());
        interceptor.afterCompletion(request, response, new Object(), null);

        AuditEventRow row = captureRow();
        assertThat(row.actorUserId()).isEqualTo(3);
        assertThat(row.organizationId()).isNull();
        assertThat(row.action()).isEqualTo(ActionType.API_UPDATE.name());
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
    }

    @Test
    void excludedActuatorPathIsNotAudited() {
        when(request.getRequestURI()).thenReturn("/actuator/health");
        when(request.getMethod()).thenReturn("GET");

        assertThat(interceptor.preHandle(request, response, new Object())).isTrue();
        interceptor.afterCompletion(request, response, new Object(), null);
        verifyNoInteractions(recorder);
    }

    @Test
    void optionsPreflightIsExcluded() {
        when(request.getRequestURI()).thenReturn("/api/v1/certs");
        when(request.getMethod()).thenReturn("OPTIONS");

        interceptor.preHandle(request, response, new Object());
        interceptor.afterCompletion(request, response, new Object(), null);
        verifyNoInteractions(recorder);
    }

    @Test
    void getAuditLogsReadIsExcluded() {
        when(request.getRequestURI()).thenReturn("/api/v1/audit-logs?page=1");
        when(request.getMethod()).thenReturn("GET");

        interceptor.preHandle(request, response, new Object());
        interceptor.afterCompletion(request, response, new Object(), null);
        verifyNoInteractions(recorder);
    }

    /** A page load or a poll is an application log line, never an audit row, on any path. */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"GET,/api/v1/certs", "GET,/api/v1/agent/health",
            "HEAD,/api/v1/certs", "get,/api/v1/users/5"})
    void aReadIsNeverPersisted(String method, String path) {
        java.util.Map<String, Object> attributes = new java.util.HashMap<>();
        lenient().doAnswer(call -> attributes.put(call.getArgument(0), call.getArgument(1)))
                .when(request).setAttribute(anyString(), any());
        lenient().when(request.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.getArgument(0)));
        when(request.getRequestURI()).thenReturn(path);
        when(request.getMethod()).thenReturn(method);
        lenient().when(response.getStatus()).thenReturn(200);

        assertThat(interceptor.preHandle(request, response, new Object())).isTrue();
        interceptor.afterCompletion(request, response, new Object(), null);

        verifyNoInteractions(recorder);
        assertThat(attributes).as("the read's start is kept for its log line").isNotEmpty();
    }

    @Test
    void afterCompletionWithNoContextDoesNothing() {
        interceptor.afterCompletion(request, response, new Object(), null);
        verifyNoInteractions(recorder);
    }

    @Test
    void patchMethodMapsToApiPatchAction() {
        when(request.getRequestURI()).thenReturn("/api/v1/users/1");
        when(request.getMethod()).thenReturn("PATCH");
        when(response.getStatus()).thenReturn(204);

        interceptor.preHandle(request, response, new Object());
        interceptor.afterCompletion(request, response, new Object(), null);

        AuditEventRow row = captureRow();
        assertThat(row.action()).isEqualTo(ActionType.API_PATCH.name());
        assertThat(row.resourceType()).isEqualTo("USER");
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
    }

    @Test
    void theRowKeepsTheMatchedRouteNeverTheRawPath() {
        when(request.getRequestURI()).thenReturn("/api/v1/certs/abc-123");
        when(request.getMethod()).thenReturn("PATCH");
        when(request.getAttribute(org.springframework.web.servlet.HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE))
                .thenReturn("/api/v1/certs/{xref}");
        when(response.getStatus()).thenReturn(200);

        interceptor.preHandle(request, response, new Object());
        interceptor.afterCompletion(request, response, new Object(), null);

        AuditEventRow row = captureRow();
        assertThat(row.details().attributes()).containsEntry("route", "/api/v1/certs/{xref}");
        assertThat(Long.parseLong(row.details().attributes().get("durationMs"))).isGreaterThanOrEqualTo(0L);
        assertThat(row.summary()).isEqualTo("PATCH /api/v1/certs/{xref} returned 200").doesNotContain("abc-123");
    }
}
