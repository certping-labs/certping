// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import tools.jackson.databind.json.JsonMapper;
import com.certmanagement.audit.AuditEventQuery;
import com.certmanagement.audit.AuditEventQueryStore;
import com.certmanagement.audit.AuditEventRecord;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.audit.AuditTrailExporter;
import com.certmanagement.audit.AuditTrailReader;
import com.certmanagement.audit.AuditTrailView;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.audit.AuditVisibilityPolicy;
import com.certmanagement.audit.AuditedReads;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import tools.jackson.databind.cfg.DateTimeFeature;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The platform view over HTTP: the JSON contract (a golden file), internal rows and staff fields, the range rules
 * (unclamped, 90 days per query, 7 days for an id search across every organization), the staff events written
 * into the organization's trail, the export, and the filter options.
 */
class AdminAuditControllerMockMvcTest {

    private static final String ADMIN_AUDIT_LOGS = "/api/v1/admin/audit-logs";
    private static final long ORG_ID = 7L;
    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");

    private final AuditEventQueryStore store = mock(AuditEventQueryStore.class);
    private final FeatureFlagService flags = mock(FeatureFlagService.class);
    private final AuditVisibilityPolicy policy = new AuditVisibilityPolicy(flags);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final AuditTrailReader reader = new AuditTrailReader(store, clock, 10_000, 90);
    private final AuditedReads reads = mock(AuditedReads.class);
    private final JsonMapper json = JsonMapper.builderWithJackson2Defaults().disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS).build();
    private final AuditTrailExporter exporter = new AuditTrailExporter(reader, store, mock(AuditEventStore.class),
            reads, json, clock, mock(PlatformTransactionManager.class), 10_000, 10, 4);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(5, null, "req-admin", "sam@example.com");
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "sam", null, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"),
                new SimpleGrantedAuthority("audit:view"))));
        when(flags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        when(flags.disabledFeatureKeysFor(anyCollection(), anyCollection())).thenReturn(Map.of());
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of());
        when(store.users(anyCollection())).thenReturn(Map.of());
        when(store.organizationNames(anyCollection())).thenReturn(Map.of());
        mvc = MockMvcBuilders.standaloneSetup(new AdminAuditController(reader, exporter, policy, reads))
                .setMessageConverters(new JacksonJsonHttpMessageConverter(json))
                .setControllerAdvice(new GlobalExceptionHandler(json))
                .build();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void thePlatformPageMatchesTheGoldenContract() throws Exception {
        when(store.list(any(), any(), eq(0L), eq(4))).thenReturn(goldenRows());
        when(store.countUpTo(any(), eq(10_001))).thenReturn(OptionalLong.of(3));
        when(store.users(anyCollection())).thenReturn(Map.of(
                5, new AuditEventQueryStore.LiveUser("sam@example.com", "Sam Support", null),
                42, new AuditEventQueryStore.LiveUser("alice@acme.test", "Alice Admin", ORG_ID)));
        when(store.organizationNames(anyCollection())).thenReturn(Map.of(ORG_ID, "Acme"));

        String body = mvc.perform(get(ADMIN_AUDIT_LOGS).param("organizationId", String.valueOf(ORG_ID))
                        .param("size", "3").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        String golden = new ClassPathResource("audit/admin-audit-log-page.golden.json")
                .getContentAsString(StandardCharsets.UTF_8);
        JSONAssert.assertEquals(golden, body, JSONCompareMode.STRICT);
    }

    @Test
    void readingAnOrganizationsTrailIsRecordedInItAndReadingEveryOrganizationIsNot() throws Exception {
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("organizationId", "7")).andExpect(status().isOk());
        verify(reads).staffRead(AuditEventType.SUPPORT_AUDIT_LOG_VIEWED, 7L);

        mvc.perform(get(ADMIN_AUDIT_LOGS)).andExpect(status().isOk());
        verify(reads).staffRead(eq(AuditEventType.SUPPORT_AUDIT_LOG_VIEWED), isNull());
    }

    @Test
    void thePlatformQueryIsUnclampedReadsBothVisibilitiesAndEveryOrganization() throws Exception {
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("from", "2025-08-01T00:00:00Z").param("to", "2025-10-01T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.visibleFrom").doesNotExist());
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("visibility", "internal").param("organizationId", "7"))
                .andExpect(status().isOk());

        ArgumentCaptor<AuditEventQuery> queries = ArgumentCaptor.forClass(AuditEventQuery.class);
        verify(store, org.mockito.Mockito.times(2)).list(queries.capture(), any(), anyLong(), anyInt());
        AuditEventQuery old = queries.getAllValues().get(0);
        assertThat(old.view()).isEqualTo(AuditTrailView.PLATFORM);
        assertThat(old.from()).isEqualTo(Instant.parse("2025-08-01T00:00:00Z"));
        assertThat(old.organizationId()).as("every organization").isNull();
        assertThat(old.visibility()).as("both visibilities").isNull();
        AuditEventQuery internal = queries.getAllValues().get(1);
        assertThat(internal.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(internal.organizationId()).isEqualTo(7L);
        assertThat(internal.to()).isEqualTo(NOW);
        assertThat(internal.from()).as("90 days before to by default").isEqualTo(NOW.minus(Duration.ofDays(90)));

        mvc.perform(get(ADMIN_AUDIT_LOGS).param("visibility", "SECRET")).andExpect(status().isBadRequest());
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("page", "2")).andExpect(status().isBadRequest());
    }

    @Test
    void aQuerySpansAtMostNinetyDays() throws Exception {
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("from", "2026-01-01T00:00:00Z").param("to", "2026-10-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("at most 90 days")));
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("from", "2020-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
        verify(store, never()).list(any(), any(), anyLong(), anyInt());
    }

    @Test
    void anIdSearchAcrossEveryOrganizationSpansAtMostSevenDays() throws Exception {
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("requestId", "req-1")
                        .param("from", NOW.minus(Duration.ofDays(8)).toString()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("at most 7 days")));
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("correlationId", "corr-1")).andExpect(status().isOk());
        mvc.perform(get(ADMIN_AUDIT_LOGS).param("requestId", "req-1").param("organizationId", "7")
                        .param("from", NOW.minus(Duration.ofDays(30)).toString()))
                .andExpect(status().isOk());

        ArgumentCaptor<AuditEventQuery> queries = ArgumentCaptor.forClass(AuditEventQuery.class);
        verify(store, org.mockito.Mockito.times(2)).list(queries.capture(), any(), anyLong(), anyInt());
        assertThat(queries.getAllValues().get(0).from()).as("7 days before to by default")
                .isEqualTo(NOW.minus(Duration.ofDays(7)));
    }

    @Test
    void aSupportExportIsRecordedInTheOrganizationsTrailBeforeAnyRowIsRead() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(1L);
        when(store.organizationNames(anyCollection())).thenReturn(Map.of(ORG_ID, "Acme"));
        when(reads.staffExport(eq(AuditEventType.SUPPORT_AUDIT_LOG_EXPORTED), eq(ORG_ID), any())).thenReturn(true);
        when(store.stream(any(), anyInt(), any())).thenAnswer(call -> {
            Consumer<List<AuditEventRecord>> chunks = call.getArgument(2);
            chunks.accept(List.of(goldenRows().get(0)));
            return 1L;
        });

        MvcResult started = mvc.perform(get(ADMIN_AUDIT_LOGS + "/export").param("organizationId", "7"))
                .andExpect(request().asyncStarted()).andReturn();
        String body = mvc.perform(asyncDispatch(started))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"certping-audit-log-acme-2026-10-07.csv\""))
                .andExpect(header().string("X-Audit-Export-Rows", "1"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body.lines().findFirst().orElseThrow()).endsWith(
                ",organizationId,organizationName,visibility,actor,staff,authMethod,userAgent,correlationId,traceId");
        assertThat(body).contains("INTERNAL,user:5,true,PASSWORD,curl/8,,4bf92f3577b34da6a3ce929d0e0e4736");
        InOrder order = inOrder(reads, store);
        ArgumentCaptor<AuditSubject> subject = ArgumentCaptor.forClass(AuditSubject.class);
        order.verify(reads).staffExport(eq(AuditEventType.SUPPORT_AUDIT_LOG_EXPORTED), eq(ORG_ID), subject.capture());
        order.verify(store).stream(any(), eq(10_000), any());
        assertThat(subject.getValue().count()).isEqualTo(1);
        assertThat(subject.getValue().format()).isEqualTo("CSV");
    }

    @Test
    void aSupportExportIsRefusedWhenItsRowCannotBeWrittenOrItIsTooLarge() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(1L);
        when(reads.staffExport(any(), any(), any())).thenReturn(false);
        mvc.perform(get(ADMIN_AUDIT_LOGS + "/export").param("organizationId", "7"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("EXPORT_NOT_RECORDED"));

        when(store.countForExport(any(), anyInt())).thenReturn(10_001L);
        mvc.perform(get(ADMIN_AUDIT_LOGS + "/export"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("EXPORT_TOO_LARGE"));
        verify(store, never()).stream(any(), anyInt(), any());
    }

    @Test
    void theOptionsAreEveryCodeInternalOnesIncluded() throws Exception {
        mvc.perform(get(ADMIN_AUDIT_LOGS + "/actions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@ == 'API_REQUEST')]").isNotEmpty())
                .andExpect(jsonPath("$[?(@ == 'USER_CREATED')]").isNotEmpty());
        mvc.perform(get(ADMIN_AUDIT_LOGS + "/resources"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@ == 'API')]").isNotEmpty());
        mvc.perform(get(ADMIN_AUDIT_LOGS + "/categories").param("organizationId", "7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.key == 'PLATFORM')]").isNotEmpty())
                .andExpect(jsonPath("$[?(@.key == 'ACCESS')]").isNotEmpty());
    }

    @Test
    void aCallerWhoIsNotASuperAdminIsRefusedEvenPastMethodSecurity() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_ORGANIZATION_ADMIN"),
                new SimpleGrantedAuthority("audit:view"))));
        for (String route : List.of(ADMIN_AUDIT_LOGS, ADMIN_AUDIT_LOGS + "/export", ADMIN_AUDIT_LOGS + "/actions",
                ADMIN_AUDIT_LOGS + "/resources", ADMIN_AUDIT_LOGS + "/categories")) {
            mvc.perform(get(route)).andExpect(status().isForbidden());
        }
        verifyNoInteractions(store, reads);
    }

    /** The rows behind the golden file: a request row, a support row in the trail, and a job's row. */
    static List<AuditEventRecord> goldenRows() {
        return List.of(
                AuditEventRecord.builder()
                        .id(9203).occurredAt(Instant.parse("2026-10-07T11:30:00Z"))
                        .visibility("INTERNAL").event("api.request").category("PLATFORM").organizationId(ORG_ID)
                        .actorType("USER").actorUserId(5).actorLabel("Sam Support").actorStaff(true)
                        .authMethod("PASSWORD").action("API_REQUEST").resourceType("API").outcome("SUCCESS")
                        .summary("POST /api/v1/credentials returned 201")
                        .details("{\"kind\":\"event\",\"attributes\":{\"method\":\"POST\","
                                + "\"route\":\"/api/v1/credentials\",\"status\":\"201\",\"durationMs\":\"84\"}}")
                        .ipAddress("198.51.100.1").userAgent("curl/8").requestId("req-9")
                        .traceId("4bf92f3577b34da6a3ce929d0e0e4736")
                        .build(),
                AuditEventRecord.builder()
                        .id(9202).occurredAt(Instant.parse("2026-10-07T11:00:00Z"))
                        .visibility("CUSTOMER").event("support.audit_log_viewed").category("ORGANIZATION")
                        .organizationId(ORG_ID).actorType("USER").actorUserId(5).actorLabel("Sam Support")
                        .actorStaff(true).authMethod("PASSWORD").action("VIEW").resourceType("AUDIT")
                        .outcome("SUCCESS").summary("Viewed the audit log")
                        .ipAddress("198.51.100.1").userAgent("curl/8").requestId("req-8")
                        .build(),
                AuditEventRecord.builder()
                        .id(9201).occurredAt(Instant.parse("2026-10-07T10:00:00Z"))
                        .visibility("CUSTOMER").event("certificate.renewed").category("CERTIFICATES")
                        .featureKey("CERTIFICATE_RENEWAL").organizationId(ORG_ID)
                        .actorType("SYSTEM").actorLabel("CertPing (automatic)").actorJob("trigger-renewals")
                        .action("RENEW").resourceType("CERTIFICATE").resourceRef("cert_1").resourceName("acme.test")
                        .outcome("SUCCESS").summary("Renewed the certificate for acme.test")
                        .details("{\"kind\":\"event\",\"attributes\":{\"requestedBy\":\"42\"}}")
                        .correlationId("corr-7")
                        .build());
    }
}
