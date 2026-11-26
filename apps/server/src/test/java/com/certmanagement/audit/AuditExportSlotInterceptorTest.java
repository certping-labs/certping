// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.exception.AuditExportRefusedException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.core.task.support.TaskExecutorAdapter;
import org.springframework.mock.web.MockAsyncContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.async.CallableProcessingInterceptor;
import org.springframework.web.context.request.async.StandardServletAsyncWebRequest;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.RejectedExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * An export's slot comes back when its async request completes even if its body never ran: the executor rejected
 * it, or the request timed out first (which ends as 503 EXPORT_TIMEOUT). Driven through Spring's own
 * {@link WebAsyncManager}, the path a {@code StreamingResponseBody} takes.
 */
class AuditExportSlotInterceptorTest {

    private static final long ORG_ID = 7L;

    private final AuditEventQueryStore store = mock(AuditEventQueryStore.class);
    private final FeatureFlagService flags = mock(FeatureFlagService.class);
    private final AuditVisibilityPolicy policy = new AuditVisibilityPolicy(flags);
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-07T12:00:00Z"), ZoneOffset.UTC);
    private final AuditTrailExporter exporter = new AuditTrailExporter(new AuditTrailReader(store, clock, 10_000, 90),
            store, mock(AuditEventStore.class), mock(AuditedReads.class), JsonMapper.builderWithJackson2Defaults().build(), clock,
            mock(PlatformTransactionManager.class), 10_000, 10, 4);
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/audit-logs/export");
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", null);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        request.setAsyncSupported(true);
        when(flags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        when(store.organizationNames(anyCollection())).thenReturn(Map.of());
        when(store.exportsSince(eq(ORG_ID), any())).thenReturn(new AuditEventQueryStore.RecentExports(0, null));
        when(store.countForExport(any(), anyInt())).thenReturn(1L);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        GatewayRequestContext.clear();
    }

    @Test
    void aBodyTheExecutorRejectedGivesItsSlotBackWhenTheRequestCompletes() throws Exception {
        AuditTrailExporter.AuditExport export = startExport();

        WebAsyncManager async = process(export, new TaskExecutorAdapter(task -> {
            throw new RejectedExecutionException("full");
        }));

        assertThat(async.getConcurrentResult()).isInstanceOf(TaskRejectedException.class);
        assertThat(exporter.availableSlots()).as("held until the request completes").isEqualTo(3);
        complete(false);
        assertThat(exporter.availableSlots()).isEqualTo(4);
        verify(store, never()).stream(any(), anyInt(), any());
    }

    @Test
    void aRequestThatTimesOutBeforeTheBodyRunsEndsAs503AndGivesItsSlotBack() throws Exception {
        AuditTrailExporter.AuditExport export = startExport();

        // An executor that accepts the body and never runs it.
        WebAsyncManager async = process(export, new TaskExecutorAdapter(task -> { }));
        complete(true);

        assertThat(async.getConcurrentResult()).isInstanceOfSatisfying(AuditExportRefusedException.class,
                refused -> {
                    assertThat(refused.getCode()).isEqualTo(AuditExportRefusedException.TIMEOUT);
                    assertThat(refused.getStatus().value()).isEqualTo(503);
                });
        assertThat(exporter.availableSlots()).isEqualTo(4);
    }

    @Test
    void theBodyAndTheInterceptorBothReleasingGiveOneSlotBack() throws Exception {
        AuditTrailExporter.AuditExport export = startExport();

        export.body().writeTo(new ByteArrayOutputStream());
        new AuditExportSlotInterceptor().afterCompletion(new ServletWebRequest(request), () -> null);

        assertThat(exporter.availableSlots()).isEqualTo(4);
    }

    @Test
    void aRequestThatIsNotAnExportIsLeftAlone() {
        AuditExportSlotInterceptor interceptor = new AuditExportSlotInterceptor();
        ServletWebRequest other = new ServletWebRequest(new MockHttpServletRequest());

        assertThat(interceptor.handleTimeout(other, () -> null))
                .isSameAs(CallableProcessingInterceptor.RESULT_NONE);
        interceptor.afterCompletion(other, () -> null);
        assertThat(exporter.availableSlots()).isEqualTo(4);
    }

    private AuditTrailExporter.AuditExport startExport() {
        when(store.stream(any(), anyInt(), any())).thenReturn(0L);
        AuditTrailExporter.AuditExport export = exporter.exportActivity(new AuditEventFilterRequest(), "csv", false,
                policy.viewer(false, ORG_ID));
        assertThat(exporter.availableSlots()).isEqualTo(3);
        assertThat(request.getAttribute(AuditTrailExporter.PERMIT_ATTRIBUTE)).isNotNull();
        return export;
    }

    /** What StreamingResponseBodyReturnValueHandler does with the body: a Callable on the async manager. */
    private WebAsyncManager process(AuditTrailExporter.AuditExport export, AsyncTaskExecutor executor)
            throws Exception {
        WebAsyncManager async = WebAsyncUtils.getAsyncManager(request);
        async.setAsyncWebRequest(new StandardServletAsyncWebRequest(request, response));
        async.setTaskExecutor(executor);
        async.registerCallableInterceptors(new AuditExportSlotInterceptor());
        async.startCallableProcessing(() -> {
            export.body().writeTo(response.getOutputStream());
            return null;
        });
        return async;
    }

    /** The container ending the async request, after a timeout or not. */
    private void complete(boolean timedOut) throws IOException {
        MockAsyncContext context = (MockAsyncContext) request.getAsyncContext();
        AsyncEvent event = new AsyncEvent(context, request, response);
        for (AsyncListener listener : context.getListeners()) {
            if (timedOut) {
                listener.onTimeout(event);
            }
        }
        for (AsyncListener listener : context.getListeners()) {
            listener.onComplete(event);
        }
    }
}
