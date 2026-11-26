// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import tools.jackson.databind.json.JsonMapper;
import com.certmanagement.aspect.FeatureGatedAspect;
import com.certmanagement.audit.AuditEventQueryStore;
import com.certmanagement.audit.AuditEventRecord;
import com.certmanagement.audit.AuditTrailExporter;
import com.certmanagement.audit.AuditTrailReader;
import com.certmanagement.audit.AuditVisibilityPolicy;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.web.SortHandlerMethodArgumentResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.cfg.DateTimeFeature;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The audit list over HTTP: the JSON contract (a golden file the app's fixtures share; a superset of the
 * legacy page), the options, a timed-out query as a 503, and the routes refused with 423 while
 * AUDIT_LOGS is off.
 */
class AuditControllerMockMvcTest {

    private static final String AUDIT_LOGS = "/api/v1/audit-logs";
    private static final long ORG_ID = 7L;
    private static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");

    private final AuditEventQueryStore store = mock(AuditEventQueryStore.class);
    private final FeatureFlagService flags = mock(FeatureFlagService.class);
    private final AuditVisibilityPolicy policy = new AuditVisibilityPolicy(flags);
    private final AuditTrailReader reader = new AuditTrailReader(store, Clock.fixed(NOW, ZoneOffset.UTC), 10_000, 90);
    /** As Spring Boot configures it: ISO dates, not timestamps. */
    private final JsonMapper json = JsonMapper.builderWithJackson2Defaults().disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS).build();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "user@example.com");
        when(flags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of());
        when(store.users(anyCollection())).thenReturn(Map.of());
        when(store.organizationNames(anyCollection())).thenReturn(Map.of());
        mvc = mvc(new AuditController(reader, policy, mock(AuditTrailExporter.class)));
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    private MockMvc mvc(AuditController controller) {
        return MockMvcBuilders.standaloneSetup(controller)
                .setCustomArgumentResolvers(new SortHandlerMethodArgumentResolver())
                .setMessageConverters(new JacksonJsonHttpMessageConverter(json))
                .setControllerAdvice(new GlobalExceptionHandler(json))
                .build();
    }

    @Test
    void thePageMatchesTheGoldenContract() throws Exception {
        when(flags.disabledFeatureKeys(ORG_ID)).thenReturn(Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT));
        when(store.list(any(), any(), eq(0L), eq(5))).thenReturn(goldenRows());
        when(store.countUpTo(any(), eq(10_001))).thenReturn(OptionalLong.of(57));
        when(store.users(anyCollection())).thenReturn(Map.of(
                42, new AuditEventQueryStore.LiveUser("alice@acme.test", "Alice Admin", ORG_ID),
                51, new AuditEventQueryStore.LiveUser("bob@acme.test", "Bob Builder", ORG_ID)));
        when(store.organizationNames(anyCollection())).thenReturn(Map.of(ORG_ID, "Acme"));

        String body = mvc.perform(get(AUDIT_LOGS).param("size", "4").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        String golden = new ClassPathResource("audit/audit-log-page.golden.json")
                .getContentAsString(StandardCharsets.UTF_8);
        JSONAssert.assertEquals(golden, body, JSONCompareMode.STRICT);
    }

    @Test
    void aSuperAdminNamesAnOrganizationAndIsNotClamped() throws Exception {
        asSuperAdmin();

        mvc.perform(get(AUDIT_LOGS).param("organizationId", "99").param("from", "2020-01-01T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.visibleFrom").doesNotExist());
    }

    @Test
    void aCustomerCannotReadAnotherOrganization() throws Exception {
        mvc.perform(get(AUDIT_LOGS).param("organizationId", "99")).andExpect(status().isForbidden());
        mvc.perform(get(AUDIT_LOGS).param("organizationId", "abc")).andExpect(status().isBadRequest());
    }

    @Test
    void aCustomerPageSaysWhereTheVisibleWindowStarts() throws Exception {
        mvc.perform(get(AUDIT_LOGS).param("from", "2020-01-01T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.visibleFrom").value("2026-07-09T12:00:00Z"));
    }

    @Test
    void aCursorWithAPageIsA400() throws Exception {
        mvc.perform(get(AUDIT_LOGS).param("cursor", "abc").param("page", "1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void sortAscendingByTimestampIsHonoured() throws Exception {
        mvc.perform(get(AUDIT_LOGS).param("sort", "timestamp,asc")).andExpect(status().isOk());

        org.mockito.ArgumentCaptor<com.certmanagement.audit.AuditEventQuery> query =
                org.mockito.ArgumentCaptor.forClass(com.certmanagement.audit.AuditEventQuery.class);
        org.mockito.Mockito.verify(store).list(query.capture(), any(), anyLong(), anyInt());
        assertThat(query.getValue().ascending()).isTrue();
    }

    @Test
    void aTimedOutQueryIsA503WithItsOwnCodeNotTheCatchAll500() throws Exception {
        when(store.list(any(), any(), anyLong(), anyInt()))
                .thenThrow(new QueryTimeoutException("audit_events query timed out"));

        mvc.perform(get(AUDIT_LOGS).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().doesNotExist(HttpHeaders.RETRY_AFTER))
                .andExpect(jsonPath("$.status").value(503))
                .andExpect(jsonPath("$.code").value("QUERY_TIMEOUT"))
                .andExpect(jsonPath("$.path").value(AUDIT_LOGS));
    }

    @Test
    void theOptionsAreCatalogAndFeatureAware() throws Exception {
        when(flags.disabledFeatureKeys(ORG_ID)).thenReturn(Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT));

        mvc.perform(get(AUDIT_LOGS + "/categories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].key").value("ACCESS_CONTROL"))
                .andExpect(jsonPath("$[0].label").value("Access control"))
                .andExpect(jsonPath("$[0].enabled").value(true))
                .andExpect(jsonPath("$[0].featureKey").doesNotExist());
        mvc.perform(get(AUDIT_LOGS + "/resources"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@ == 'CREDENTIAL')]").isEmpty())
                .andExpect(jsonPath("$[?(@ == 'USER')]").isNotEmpty());
        mvc.perform(get(AUDIT_LOGS + "/actions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@ == 'USER_CREATED')]").isNotEmpty());

        asSuperAdmin();
        mvc.perform(get(AUDIT_LOGS + "/resources").param("organizationId", String.valueOf(ORG_ID)))
                .andExpect(jsonPath("$[?(@ == 'CREDENTIAL')]").isNotEmpty());
    }

    @Test
    void everyRouteIsRefusedWith423WhileAuditLogsIsOff() throws Exception {
        doThrow(new FeatureDisabledException(FeatureFlags.AUDIT_LOGS))
                .when(flags).assertEnabled(FeatureFlags.AUDIT_LOGS, ORG_ID);
        AuditTrailReader untouched = mock(AuditTrailReader.class);
        AuditVisibilityPolicy untouchedPolicy = mock(AuditVisibilityPolicy.class);
        AuditTrailExporter untouchedExporter = mock(AuditTrailExporter.class);
        AspectJProxyFactory factory = new AspectJProxyFactory(
                new AuditController(untouched, untouchedPolicy, untouchedExporter));
        factory.setProxyTargetClass(true);
        factory.addAspect(new FeatureGatedAspect(flags));
        MockMvc gated = mvc(factory.getProxy());

        for (String route : List.of(AUDIT_LOGS, AUDIT_LOGS + "/categories", AUDIT_LOGS + "/resources",
                AUDIT_LOGS + "/actions", AUDIT_LOGS + "/export", AUDIT_LOGS + "/access", AUDIT_LOGS + "/access/export",
                AUDIT_LOGS + "/access/activities")) {
            gated.perform(get(route)).andExpect(status().is(423))
                    .andExpect(jsonPath("$.feature").value(FeatureFlags.AUDIT_LOGS));
        }
        verifyNoInteractions(untouched, untouchedPolicy, untouchedExporter);
    }

    private static void asSuperAdmin() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
    }

    /** The rows behind the golden file. */
    private static List<AuditEventRecord> goldenRows() {
        return List.of(
                AuditEventRecord.builder()
                        .id(9004).occurredAt(Instant.parse("2026-10-07T11:59:00.123456Z"))
                        .event("credential.deleted").category("CREDENTIALS")
                        .featureKey(FeatureFlags.CREDENTIALS_MANAGEMENT).organizationId(ORG_ID)
                        .actorType("USER").actorUserId(42).actorLabel("Alice Admin")
                        .action("DELETE").resourceType("CREDENTIAL").resourceRef("cred_8f2k").resourceName("prod-dns")
                        .outcome("SUCCESS").summary("Deleted the Azure credential 'prod-dns'")
                        .details("{\"kind\":\"event\",\"attributes\":{\"credentialType\":\"DNS\"}}")
                        .ipAddress("203.0.113.7").userAgent("Mozilla/5.0").requestId("req-4").correlationId("corr-4")
                        .build(),
                AuditEventRecord.builder()
                        .id(9003).occurredAt(Instant.parse("2026-10-07T11:00:00Z"))
                        .event("member.roles_changed").category("ACCESS_CONTROL").organizationId(ORG_ID)
                        .actorType("USER").actorUserId(42).actorLabel("Alice Admin")
                        .action("USER_ROLES_CHANGED").resourceType("USER").resourceId(51L).resourceRef("51")
                        .outcome("SUCCESS").summary("Changed a member's roles")
                        .details("{\"kind\":\"event\",\"changes\":[{\"field\":\"roles\",\"before\":\"VIEWER\","
                                + "\"after\":\"ADMIN\"}],\"attributes\":{\"added\":\"ADMIN\",\"removed\":\"VIEWER\"}}")
                        .ipAddress("203.0.113.7").requestId("req-3")
                        .build(),
                AuditEventRecord.builder()
                        .id(9002).occurredAt(Instant.parse("2026-10-07T10:00:00Z"))
                        .event("auth.account_locked").category("AUTHENTICATION").organizationId(ORG_ID)
                        .actorType("SYSTEM").actorLabel("CertPing (automatic)")
                        .action("ACCOUNT_LOCK").resourceType("USER").resourceId(77L).resourceRef("77")
                        .outcome("SUCCESS").summary("a member's account was locked after 5 failed sign-ins")
                        .details("{\"kind\":\"event\",\"attributes\":{\"attempts\":\"5\"}}")
                        .correlationId("corr-2")
                        .build(),
                AuditEventRecord.builder()
                        .id(9001).occurredAt(Instant.parse("2026-10-07T09:00:00Z"))
                        .event("credential.created").category("CREDENTIALS")
                        .featureKey(FeatureFlags.CREDENTIALS_MANAGEMENT).organizationId(ORG_ID)
                        .actorType("USER").actorUserId(43).actorLabel("Former member")
                        .action("CREATE").resourceType("CREDENTIAL").resourceName("staging-dns")
                        .outcome("FAILURE").errorCode("PERMISSION_DENIED")
                        .summary("Could not add the Azure credential 'staging-dns'")
                        .ipAddress("198.51.100.9").requestId("req-1")
                        .build(),
                AuditEventRecord.builder()
                        .id(9000).occurredAt(Instant.parse("2026-10-07T08:00:00Z"))
                        .event("auth.signed_in").category("AUTHENTICATION").organizationId(ORG_ID)
                        .actorType("USER").actorUserId(42).actorLabel("Alice Admin")
                        .action("SIGN_IN").resourceType("AUTH").outcome("SUCCESS").summary("Signed in")
                        .build());
    }
}
