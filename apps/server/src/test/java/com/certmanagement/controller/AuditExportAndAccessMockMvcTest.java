// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import tools.jackson.databind.json.JsonMapper;
import com.certmanagement.audit.AuditEventQuery;
import com.certmanagement.audit.AuditEventQueryStore;
import com.certmanagement.audit.AuditEventRecord;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditTrailExporter;
import com.certmanagement.audit.AuditTrailReader;
import com.certmanagement.audit.AuditTrailView;
import com.certmanagement.audit.AuditVisibilityPolicy;
import com.certmanagement.audit.AuditedReads;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.web.SortHandlerMethodArgumentResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import tools.jackson.databind.cfg.DateTimeFeature;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The customer export and the Access view over HTTP, with the real reader and exporter over a mocked store: the
 * export is recorded before any row is read (and refused when it cannot be), its limits (row cap, exports per
 * hour), the file (name, type, CSV header, formula guard, JSON), and the Access view's contract.
 */
class AuditExportAndAccessMockMvcTest {

    private static final String AUDIT_LOGS = "/api/v1/audit-logs";
    private static final long ORG_ID = 7L;
    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");

    private final AuditEventQueryStore store = mock(AuditEventQueryStore.class);
    private final AuditEventStore events = mock(AuditEventStore.class);
    private final FeatureFlagService flags = mock(FeatureFlagService.class);
    private final AuditVisibilityPolicy policy = new AuditVisibilityPolicy(flags);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final AuditTrailReader reader = new AuditTrailReader(store, clock, 10_000, 90);
    private final JsonMapper json = JsonMapper.builderWithJackson2Defaults().disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS).build();
    private final AuditTrailExporter exporter = new AuditTrailExporter(reader, store, events, mock(AuditedReads.class),
            json, clock, mock(PlatformTransactionManager.class), 10_000, 10, 4);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-export", "user@example.com");
        when(flags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        when(store.users(anyCollection())).thenReturn(Map.of(
                42, new AuditEventQueryStore.LiveUser("alice@acme.test", "Alice Admin", ORG_ID)));
        when(store.organizationNames(anyCollection())).thenReturn(Map.of(ORG_ID, "Acme Corp"));
        when(store.exportsSince(eq(ORG_ID), any())).thenReturn(new AuditEventQueryStore.RecentExports(0, null));
        mvc = MockMvcBuilders.standaloneSetup(new AuditController(reader, policy, exporter))
                .setCustomArgumentResolvers(new SortHandlerMethodArgumentResolver())
                .setMessageConverters(new JacksonJsonHttpMessageConverter(json))
                .setControllerAdvice(new GlobalExceptionHandler(json))
                .build();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    // ── Export ───────────────────────────────────────────────────────────

    @Test
    void anExportIsRecordedBeforeAnyRowIsReadThenStreamedAsCsv() throws Exception {
        when(store.countForExport(any(), eq(10_001))).thenReturn(2L);
        streams(List.of(row(2, "=HYPERLINK(\"http://evil\")"),
                row(1, "Signed in")));

        String body = download(get(AUDIT_LOGS + "/export").param("format", "csv"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-log-acme-corp-2026-10-07.csv\""))
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, "text/csv;charset=UTF-8"))
                .andExpect(header().string("X-Audit-Export-Rows", "2"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        List<String> lines = body.lines().toList();
        assertThat(lines.get(0)).isEqualTo("timestamp,action,event,summary,status,errorCode,resource,resourceId,"
                + "resourceName,actorType,actorName,userId,userEmail,ipAddress,requestId,category,reason,requestedByName");
        assertThat(lines).hasSize(3);
        assertThat(lines.get(1)).as("formula guard").contains(",\"'=HYPERLINK(\"\"http://evil\"\")\",");
        assertThat(lines.get(2)).contains("Signed in,SUCCESS").contains("Alice Admin,42,alice@acme.test");

        InOrder order = inOrder(store, events);
        order.verify(store).lockExports(ORG_ID);
        order.verify(store).exportsSince(eq(ORG_ID), eq(NOW.minusSeconds(3600)));
        order.verify(store).countForExport(any(), eq(10_001));
        ArgumentCaptor<AuditEventRow> recorded = ArgumentCaptor.forClass(AuditEventRow.class);
        order.verify(events).insert(recorded.capture());
        ArgumentCaptor<AuditEventQuery> streamed = ArgumentCaptor.forClass(AuditEventQuery.class);
        order.verify(store).stream(streamed.capture(), eq(10_000), any());

        AuditEventRow row = recorded.getValue();
        assertThat(row.event()).isEqualTo("audit_log.exported");
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(row.organizationId()).isEqualTo(ORG_ID);
        assertThat(row.summary()).isEqualTo("Exported 2 audit log entries as CSV");
        assertThat(row.details().attributes()).containsEntry("format", "CSV")
                .containsEntry("to", NOW.toString()).containsKey("from");

        AuditEventQuery query = streamed.getValue();
        assertThat(query.view()).isEqualTo(AuditTrailView.ACTIVITY);
        assertThat(query.category()).as("sensitive reads are left out in SQL unless asked for").isNull();
        assertThat(query.organizationId()).isEqualTo(ORG_ID);
        assertThat(query.from()).as("clamped to the visible window").isEqualTo(NOW.minus(java.time.Duration.ofDays(90)));
        assertThat(query.to()).as("the end is fixed when the export is recorded").isEqualTo(NOW);
    }

    @Test
    void aResourceNameASpreadsheetWouldRunIsExportedAsText() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(1L);
        streams(List.of(row(1, "Deleted the credential").toBuilder().event("credential.deleted")
                .category("CREDENTIALS").action("DELETE").resourceType("CREDENTIAL")
                .resourceName("=HYPERLINK(\"http://x\",\"y\")").build()));

        String body = download(get(AUDIT_LOGS + "/export"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body.lines().toList().get(1)).contains(",\"'=HYPERLINK(\"\"http://x\"\",\"\"y\"\")\",");
    }

    @Test
    void anExportWaitingTooLongForAnotherExportOfTheOrganizationIsAskedToRetry() throws Exception {
        doThrow(new org.springframework.dao.CannotAcquireLockException("lock timeout",
                new java.sql.SQLException("canceling statement due to lock timeout", "55P03")))
                .when(store).lockExports(ORG_ID);

        mvc.perform(get(AUDIT_LOGS + "/export"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "5"))
                .andExpect(jsonPath("$.code").value("EXPORT_IN_PROGRESS"));
        verify(events, never()).insert(any());
    }

    @Test
    void aPodStreamsAtMostItsConcurrencyOfExportsAndARefusalFreesItsSlot() throws Exception {
        AuditTrailExporter onePerPod = new AuditTrailExporter(reader, store, events, mock(AuditedReads.class), json,
                clock, mock(PlatformTransactionManager.class), 10_000, 10, 1);
        MockMvc single = MockMvcBuilders.standaloneSetup(new AuditController(reader, policy, onePerPod))
                .setCustomArgumentResolvers(new SortHandlerMethodArgumentResolver())
                .setMessageConverters(new JacksonJsonHttpMessageConverter(json))
                .setControllerAdvice(new GlobalExceptionHandler(json))
                .build();
        when(store.countForExport(any(), anyInt())).thenReturn(10_001L, 1L);
        streams(List.of());

        single.perform(get(AUDIT_LOGS + "/export")).andExpect(status().isBadRequest());
        // The refusal gave its slot back: this export takes it, and holds it until its body has run.
        AuditTrailExporter.AuditExport running = onePerPod.exportActivity(new com.certmanagement.dto.audit
                .AuditEventFilterRequest(), "csv", false, policy.viewer(false, ORG_ID));

        single.perform(get(AUDIT_LOGS + "/export"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "10"))
                .andExpect(jsonPath("$.code").value("EXPORT_BUSY"));
        verify(store, org.mockito.Mockito.times(2)).lockExports(ORG_ID);

        running.body().writeTo(new java.io.ByteArrayOutputStream());
        download(single, get(AUDIT_LOGS + "/export"));
    }

    @Test
    void aJsonExportIsAnArrayOfTheListsEntries() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(1L);
        streams(List.of(row(1, "Signed in")));

        String body = download(get(AUDIT_LOGS + "/export").param("format", "json"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-log-acme-corp-2026-10-07.json\""))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        JsonNode entries = json.readTree(body);
        assertThat(entries.isArray()).isTrue();
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).get("summary").asString()).isEqualTo("Signed in");
        assertThat(entries.get(0).get("timestamp").asString()).isEqualTo("2026-10-07T11:00:01Z");
        assertThat(entries.get(0).has("requestedByName")).isTrue();
    }

    @Test
    void anExportOfMoreThanTenThousandRowsIsRefusedAndRecordedAsFailed() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(10_001L);

        mvc.perform(get(AUDIT_LOGS + "/export"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("EXPORT_TOO_LARGE"))
                .andExpect(jsonPath("$.maxRows").value(10_000))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Narrow the date range")));

        ArgumentCaptor<AuditEventRow> recorded = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(events).insert(recorded.capture());
        assertThat(recorded.getValue().outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(recorded.getValue().errorCode()).isEqualTo("EXPORT_TOO_LARGE");
        verify(store, never()).stream(any(), anyInt(), any());
    }

    @Test
    void theEleventhExportInAnHourIsRefusedUntilTheOldestLeavesTheWindow() throws Exception {
        when(store.exportsSince(eq(ORG_ID), any()))
                .thenReturn(new AuditEventQueryStore.RecentExports(10, NOW.minusSeconds(1200)));

        mvc.perform(get(AUDIT_LOGS + "/export"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "2400"))
                .andExpect(jsonPath("$.code").value("EXPORT_LIMIT"));

        verify(events, never()).insert(any());
        verify(store, never()).countForExport(any(), anyInt());
        verify(store, never()).stream(any(), anyInt(), any());
    }

    @Test
    void anExportWhoseOwnRowCannotBeWrittenIsRefusedAndNothingIsRead() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(3L);
        doThrow(new DataAccessResourceFailureException("audit_events is unavailable")).when(events).insert(any());

        mvc.perform(get(AUDIT_LOGS + "/export").header(HttpHeaders.ACCEPT, "text/csv"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("EXPORT_NOT_RECORDED"));

        verify(store, never()).stream(any(), anyInt(), any());
    }

    @Test
    void anExportTakesNoCursorAndOnlyCsvOrJson() throws Exception {
        mvc.perform(get(AUDIT_LOGS + "/export").param("cursor", "abc")).andExpect(status().isBadRequest());
        mvc.perform(get(AUDIT_LOGS + "/export").param("format", "xml")).andExpect(status().isBadRequest());
        verify(events, never()).insert(any());
    }

    @Test
    void aSuperAdminExportsANamedOrganizationOnly() throws Exception {
        asSuperAdmin();
        GatewayRequestContext.set(1, null, "req-export", "admin@example.com");
        mvc.perform(get(AUDIT_LOGS + "/export")).andExpect(status().isBadRequest());

        when(store.exportsSince(eq(99L), any())).thenReturn(new AuditEventQueryStore.RecentExports(0, null));
        when(store.organizationNames(anyCollection())).thenReturn(Map.of());
        streams(List.of());
        download(get(AUDIT_LOGS + "/export").param("organizationId", "99"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-log-org-99-2026-10-07.csv\""));
        ArgumentCaptor<AuditEventRow> recorded = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(events).insert(recorded.capture());
        assertThat(recorded.getValue().organizationId()).isEqualTo(99L);
        assertThat(recorded.getValue().actorStaff()).as("read by the customer as Platform administrator").isTrue();
    }

    @Test
    void aSuperAdminWhoNamesNoOrganizationExportsTheOneTheyWorkIn() throws Exception {
        asSuperAdmin();
        when(store.exportsSince(eq(ORG_ID), any())).thenReturn(new AuditEventQueryStore.RecentExports(0, null));
        when(store.organizationNames(anyCollection())).thenReturn(Map.of());
        streams(List.of());
        download(get(AUDIT_LOGS + "/export"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-log-org-7-2026-10-07.csv\""));
    }

    // ── Access view ──────────────────────────────────────────────────────

    @Test
    void theAccessViewListsReadsInDomainsShapeAndMasksSupport() throws Exception {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                AuditEventRecord.builder().id(9102).occurredAt(Instant.parse("2026-10-07T11:00:00Z"))
                        .event("access.agent_connection_viewed").category("ACCESS").organizationId(ORG_ID)
                        .actorType("USER").actorUserId(42).actorLabel("Alice Admin").action("VIEW_SECRET")
                        .resourceType("AGENT").outcome("SUCCESS").summary("Viewed the agent's connection string")
                        .ipAddress("203.0.113.7").userAgent("Mozilla/5.0").requestId("req-2").build(),
                AuditEventRecord.builder().id(9101).occurredAt(Instant.parse("2026-10-07T10:00:00Z"))
                        .event("access.audit_log_viewed").category("ACCESS").organizationId(ORG_ID)
                        .actorType("USER").actorUserId(5).actorLabel("Sam Support").actorStaff(true).action("VIEW")
                        .resourceType("AUDIT").outcome("SUCCESS").summary("Viewed the audit log")
                        .ipAddress("198.51.100.1").userAgent("curl").requestId("req-1").build()));

        mvc.perform(get(AUDIT_LOGS + "/access").param("activity", "access.agent_connection_viewed"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].activity").value("access.agent_connection_viewed"))
                .andExpect(jsonPath("$.content[0].actor").value("Alice Admin"))
                .andExpect(jsonPath("$.content[0].userEmail").value("alice@acme.test"))
                .andExpect(jsonPath("$.content[0].ipAddress").value("203.0.113.7"))
                .andExpect(jsonPath("$.content[1].actor").value("Platform administrator"))
                .andExpect(jsonPath("$.content[1].userId").doesNotExist())
                .andExpect(jsonPath("$.content[1].ipAddress").doesNotExist())
                .andExpect(jsonPath("$.content[1].userAgent").doesNotExist())
                .andExpect(jsonPath("$.visibleFrom").value("2026-07-09T12:00:00Z"))
                .andExpect(jsonPath("$.totalElementsCapped").value(false))
                .andExpect(jsonPath("$.nextCursor").doesNotExist());

        ArgumentCaptor<AuditEventQuery> query = ArgumentCaptor.forClass(AuditEventQuery.class);
        verify(store).list(query.capture(), any(), anyLong(), anyInt());
        assertThat(query.getValue().view()).isEqualTo(AuditTrailView.ACCESS);
        assertThat(query.getValue().events()).containsExactly("access.agent_connection_viewed");
    }

    @Test
    void theAccessViewPagesByCursorAndKnowsItsActivities() throws Exception {
        mvc.perform(get(AUDIT_LOGS + "/access").param("page", "1")).andExpect(status().isBadRequest());
        mvc.perform(get(AUDIT_LOGS + "/access").param("activity", "credential.deleted"))
                .andExpect(status().isBadRequest());
        mvc.perform(get(AUDIT_LOGS + "/access/activities"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@ == 'access.agent_connection_viewed')]").isNotEmpty())
                .andExpect(jsonPath("$[?(@ == 'credential.deleted')]").isEmpty());
    }

    @Test
    void theAccessExportIsRecordedAsAnAccessLogExport() throws Exception {
        when(store.countForExport(any(), anyInt())).thenReturn(0L);
        streams(List.of());

        String body = download(get(AUDIT_LOGS + "/access/export"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"access-log-acme-corp-2026-10-07.csv\""))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body).isEqualTo("timestamp,activity,target,resourceId,status,errorCode,actor,userId,userEmail,"
                + "ipAddress,requestId,correlationId\r\n");
        ArgumentCaptor<AuditEventRow> recorded = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(events).insert(recorded.capture());
        assertThat(recorded.getValue().event()).isEqualTo("access_log.exported");
        assertThat(recorded.getValue().summary()).isEqualTo("Exported 0 access log entries as CSV");
        ArgumentCaptor<AuditEventQuery> streamed = ArgumentCaptor.forClass(AuditEventQuery.class);
        verify(store).stream(streamed.capture(), anyInt(), any());
        assertThat(streamed.getValue().view()).isEqualTo(AuditTrailView.ACCESS);
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private ResultActions download(MockHttpServletRequestBuilder request) throws Exception {
        return download(mvc, request);
    }

    private static ResultActions download(MockMvc mvc, MockHttpServletRequestBuilder request) throws Exception {
        MvcResult started = mvc.perform(request).andExpect(request().asyncStarted()).andReturn();
        return mvc.perform(asyncDispatch(started)).andExpect(status().isOk());
    }

    @SuppressWarnings("unchecked")
    private void streams(List<AuditEventRecord> rows) {
        when(store.stream(any(), anyInt(), any())).thenAnswer(call -> {
            Consumer<List<AuditEventRecord>> chunks = call.getArgument(2);
            if (!rows.isEmpty()) {
                chunks.accept(rows);
            }
            return (long) rows.size();
        });
    }

    private static AuditEventRecord row(long id, String summary) {
        return AuditEventRecord.builder()
                .id(id).occurredAt(NOW.minusSeconds(3600).plusSeconds(id))
                .event("auth.signed_in").category("AUTHENTICATION").organizationId(ORG_ID)
                .actorType("USER").actorUserId(42).actorLabel("Alice Admin")
                .action("SIGN_IN").resourceType("AUTH").outcome("SUCCESS").summary(summary)
                .ipAddress("203.0.113.7").requestId("req-" + id)
                .build();
    }

    private static void asSuperAdmin() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
    }
}
