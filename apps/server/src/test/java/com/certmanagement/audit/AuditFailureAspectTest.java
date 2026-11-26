// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.aspect.FeatureGatedAspect;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.exception.LastOrganizationAdminException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link AuditFailure} through real Spring proxies: the aspect runs outside {@code @PreAuthorize} method
 * security, {@code FeatureGatedAspect} and {@code @Transactional}, so a permission denial and a switched-off
 * feature are recorded, after the method's transaction has ended. A {@code @Valid} body refused before the
 * method ran is recorded by {@code GlobalExceptionHandler}, a 4xx {@code ResponseEntity} by the aspect, and
 * every refused request has exactly one row.
 */
class AuditFailureAspectTest {

    private static final long ORG_ID = 7L;
    private static final long OTHER_ORG_ID = 99L;
    /** Fixed, so the per-minute caps never roll over mid-test. */
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:30Z"), ZoneOffset.UTC);

    private AnnotationConfigApplicationContext context;
    private AuditRecorder recorder;
    private FeatureFlagService flags;
    private MockMvc mvc;
    private final List<Boolean> transactionActiveWhenRecorded = new ArrayList<>();

    @Configuration
    @EnableMethodSecurity
    @EnableAspectJAutoProxy
    @EnableTransactionManagement
    static class Wiring {
        @Bean
        @DependsOnDatabaseInitialization
        AuditRecorder auditRecorder() { return mock(AuditRecorder.class); }
        @Bean FeatureFlagService featureFlagService() { return mock(FeatureFlagService.class); }
        @Bean AuditFailures auditFailures(AuditRecorder recorder) {
            return new AuditFailures(recorder, CLOCK);
        }
        @Bean Changes changes() { return new Changes(); }
        @Bean AuditFailureAspect auditFailureAspect(AuditFailures failures) { return new AuditFailureAspect(failures); }
        @Bean FeatureGatedAspect featureGatedAspect(FeatureFlagService flags) { return new FeatureGatedAspect(flags); }
        @Bean PlatformTransactionManager transactionManager() { return new NoOpTransactionManager(); }
        @Bean Endpoints endpoints() { return new Endpoints(); }
    }

    record Toggle(@NotNull Boolean enabled) {
    }

    @RestController
    static class Endpoints {

        @PostMapping("/members/{id}/disable")
        @PreAuthorize("hasRole('ORGANIZATION_ADMIN')")
        @Transactional
        @AuditFailure(value = AuditEventType.MEMBER_DISABLED, target = "#id", organization = "#organizationId")
        public ResponseEntity<Void> disable(@PathVariable Integer id, @RequestParam(required = false) Long organizationId) {
            if (id == 13) {
                throw new LastOrganizationAdminException();
            }
            if (id == 14) {
                throw new ConstraintViolationException("member 14 is not valid", Set.of());
            }
            return ResponseEntity.noContent().build();
        }

        @PutMapping("/integrations/{reference}")
        @FeatureGated(FeatureFlags.INTEGRATIONS)
        @PreAuthorize("hasRole('ORGANIZATION_ADMIN')")
        @Transactional
        @AuditFailure(value = AuditEventType.INTEGRATION_UPDATED, target = "#reference",
                instead = AuditEventType.INTEGRATION_DELETED, insteadWhen = "#body.enabled == false")
        public ResponseEntity<Void> toggle(@PathVariable String reference, @Valid @RequestBody Toggle body) {
            return ResponseEntity.ok().build();
        }

        @PutMapping("/retention/{orgId}")
        @PreAuthorize("hasRole('SUPER_ADMIN')")
        @AuditFailure(value = AuditEventType.DATA_RETENTION_CHANGED, target = "#orgId", organization = "#orgId")
        public ResponseEntity<String> retention(@PathVariable Long orgId, @RequestParam String days) {
            return days.matches("[0-9]+") ? ResponseEntity.ok(days) : ResponseEntity.badRequest().body("days");
        }

        @org.springframework.beans.factory.annotation.Autowired private Changes changes;

        @PostMapping("/members/{id}/enable")
        @PreAuthorize("hasRole('ORGANIZATION_ADMIN')")
        @AuditFailure(value = AuditEventType.MEMBER_ENABLED, target = "#id")
        public ResponseEntity<Void> enable(@PathVariable Integer id, @RequestParam String mode) {
            changes.enable(id, !"fail-inside".equals(mode));
            if ("commit-then-fail".equals(mode)) {
                throw new IllegalStateException("the response could not be built");
            }
            return ResponseEntity.noContent().build();
        }

        @org.springframework.web.bind.annotation.DeleteMapping("/domains/{domain}/deployment-targets/{credentialXref}")
        @PreAuthorize("hasRole('ORGANIZATION_ADMIN')")
        @Transactional
        @AuditFailure(value = AuditEventType.DEPLOYMENT_TARGET_REMOVED, target = "#credentialXref", domain = "#domain")
        public ResponseEntity<Void> removeTarget(@PathVariable String domain, @PathVariable String credentialXref) {
            throw new com.certmanagement.exception.CredentialRejectedException(
                    com.certmanagement.exception.CredentialRejectedException.NOT_ACTIVE,
                    "credentialXref '" + credentialXref + "' at https://example-vault-x.vault.azure.net is not ACTIVE");
        }

        @PutMapping("/platform/retention")
        @PreAuthorize("hasRole('SUPER_ADMIN')")
        @AuditFailure(value = AuditEventType.PLATFORM_SETTING_CHANGED, name = "'soft_delete_retention_days'")
        public ResponseEntity<String> platformRetention(@RequestParam String days) {
            return ResponseEntity.badRequest().body("days");
        }
    }

    /** A change whose success row is written, as in production, by a real {@link AuditRecorder}. */
    static class Changes {
        private final AuditRecorder realRecorder = new AuditRecorder(mock(AuditEventStore.class),
                mock(AuditAsyncWriter.class), new NoOpTransactionManager(), mock(javax.sql.DataSource.class));

        /** Records the success and commits; or, when {@code commit} is false, fails inside the transaction. */
        @Transactional
        public void enable(int id, boolean commit) {
            realRecorder.record(AuditEvents.success(AuditEventType.MEMBER_ENABLED,
                    AuditSubject.builder().resourceId((long) id).resourceRef(Integer.toString(id)).build()));
            if (!commit) {
                throw new IllegalStateException("rolled back");
            }
        }
    }

    /** A transaction manager that holds nothing, so {@code @Transactional} opens a real (synchronised) scope. */
    static class NoOpTransactionManager extends AbstractPlatformTransactionManager {
        @Override protected Object doGetTransaction() { return new Object(); }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { }
        @Override protected void doCommit(DefaultTransactionStatus status) { }
        @Override protected void doRollback(DefaultTransactionStatus status) { }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        recorder = context.getBean(AuditRecorder.class);
        flags = context.getBean(FeatureFlagService.class);
        reset(recorder);
        doAnswer(invocation -> {
            transactionActiveWhenRecorded.add(TransactionSynchronizationManager.isActualTransactionActive());
            return null;
        }).when(recorder).recordFailure(any());
        mvc = MockMvcBuilders.standaloneSetup(context.getBean(Endpoints.class))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build(), context.getBean(AuditFailures.class)))
                .build();
        GatewayRequestContext.set(5, String.valueOf(ORG_ID), "req-1", null);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
        context.close();
    }

    @Test
    void aPreAuthorizeDenialIsRecordedAsPermissionDenied() throws Exception {
        as("VIEWER");

        mvc.perform(post("/members/21/disable")).andExpect(status().isForbidden());

        AuditEventRow row = onlyFailure();
        assertThat(row.event()).isEqualTo("member.disabled");
        assertThat(row.errorCode()).isEqualTo("PERMISSION_DENIED");
        assertThat(row.summary()).isEqualTo("Could not disable a member");
        assertThat(row.resourceRef()).isEqualTo("21");
        assertThat(row.organizationId()).isEqualTo(ORG_ID);
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.actorUserId()).isEqualTo(5);
    }

    @Test
    void aRefusedCredentialChangeIsRecordedWithItsCodeTheDomainAndNoMessage() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .delete("/domains/example.com/deployment-targets/cred-17"))
                .andExpect(status().isBadRequest());

        AuditEventRow row = onlyFailure();
        assertThat(row.event()).isEqualTo("deployment_target.removed");
        assertThat(row.errorCode()).isEqualTo("CREDENTIAL_NOT_ACTIVE");
        assertThat(row.resourceRef()).isEqualTo("cred-17");
        assertThat(row.summary()).isEqualTo("Could not remove the deployment target from example.com");
        assertThat(row.toString()).doesNotContain("vault.azure.net").doesNotContain("is not ACTIVE");
        assertThat(transactionActiveWhenRecorded).containsExactly(false);
    }

    @Test
    void aSwitchedOffFeatureIsRecordedAsFeatureDisabled() throws Exception {
        as("ORGANIZATION_ADMIN");
        doThrow(new FeatureDisabledException(FeatureFlags.INTEGRATIONS)).when(flags)
                .assertEnabled(anyString(), any());

        mvc.perform(put("/integrations/slack-7").contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                .andExpect(status().is(423));

        AuditEventRow row = onlyFailure();
        assertThat(row.event()).as("the body chose the event").isEqualTo("integration.deleted");
        assertThat(row.errorCode()).isEqualTo("FEATURE_DISABLED");
        assertThat(row.resourceRef()).isEqualTo("slack-7");
    }

    @Test
    void aValidFailureBeforeTheMethodRanIsRecordedAsInvalidInputByTheExceptionHandler() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(put("/integrations/slack-7").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());

        AuditEventRow row = onlyFailure();
        assertThat(row.event()).isEqualTo("integration.updated");
        assertThat(row.errorCode()).isEqualTo("INVALID_INPUT");
        assertThat(row.resourceRef()).as("path variables are known before the method ran")
                .isEqualTo("slack-7");
    }

    @Test
    void anUnreadableBodyIsRecordedAsInvalidInput() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(put("/integrations/slack-7").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest());

        assertThat(onlyFailure().errorCode()).isEqualTo("INVALID_INPUT");
    }

    @Test
    void aFourHundredResponseEntityIsRecorded() throws Exception {
        asSuperAdmin();

        mvc.perform(put("/retention/" + OTHER_ORG_ID).param("days", "soon")).andExpect(status().isBadRequest());

        AuditEventRow row = onlyFailure();
        assertThat(row.event()).isEqualTo("data_retention.changed");
        assertThat(row.errorCode()).isEqualTo("INVALID_INPUT");
        assertThat(row.organizationId()).as("a super admin's failure lands in the organization acted on")
                .isEqualTo(OTHER_ORG_ID);
        assertThat(row.actorStaff()).isTrue();
    }

    @Test
    void aFailedPlatformSettingIsAnInternalRow() throws Exception {
        asSuperAdmin();

        mvc.perform(put("/platform/retention").param("days", "x")).andExpect(status().isBadRequest());

        AuditEventRow row = onlyFailure();
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.summary()).isEqualTo("Could not change the platform setting 'soft_delete_retention_days'");
    }

    @Test
    void aThrownRefusalIsRecordedOnceWithItsCodeAfterTheTransactionEnded() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(post("/members/13/disable")).andExpect(status().isConflict());

        assertThat(onlyFailure().errorCode()).isEqualTo("LAST_ORGANIZATION_ADMIN");
        assertThat(transactionActiveWhenRecorded).as("recorded outside @Transactional").containsExactly(false);
    }

    @Test
    void aRefusalTheExceptionHandlerAlsoSeesIsRecordedOnce() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(post("/members/14/disable")).andExpect(status().isBadRequest());

        assertThat(onlyFailure().errorCode()).isEqualTo("INVALID_INPUT");
    }

    @Test
    void anOrganizationAdminCannotWriteIntoAnotherOrganizationsTrail() throws Exception {
        as("VIEWER");

        mvc.perform(post("/members/21/disable").param("organizationId", String.valueOf(OTHER_ORG_ID)))
                .andExpect(status().isForbidden());

        assertThat(onlyFailure().organizationId()).isEqualTo(ORG_ID);
    }

    @Test
    void aStaffMemberWithNoOrganizationGetsAnInternalRow() throws Exception {
        GatewayRequestContext.set(1, null, "req-2", null);
        as("VIEWER");

        mvc.perform(post("/members/21/disable")).andExpect(status().isForbidden());

        AuditEventRow row = onlyFailure();
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.organizationId()).isNull();
    }

    @Test
    void aSuccessIsNotAFailure() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(post("/members/21/disable")).andExpect(status().isNoContent());
        mvc.perform(put("/integrations/slack-7").contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":true}"))
                .andExpect(status().isOk());

        verify(recorder, never()).recordFailure(any());
    }

    private AuditEventRow onlyFailure() {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, org.mockito.Mockito.atLeast(0)).recordFailure(rows.capture());
        assertThat(rows.getAllValues()).as("exactly one failure row per refused request").hasSize(1);
        return rows.getValue();
    }

    private static void as(String role) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role))));
    }

    private static void asSuperAdmin() {
        GatewayRequestContext.set(1, null, "req-3", null);
        as("SUPER_ADMIN");
    }

    // ── One outcome per request ──────────────────────────────────────────

    @Test
    void aRequestWhoseSuccessCommittedRecordsNoFailureForALaterError() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(post("/members/21/enable").param("mode", "commit-then-fail"))
                .andExpect(status().isInternalServerError());

        verify(recorder, never()).recordFailure(any());
    }

    @Test
    void aSuccessRowThatRolledBackLeavesTheFailureToBeRecorded() throws Exception {
        as("ORGANIZATION_ADMIN");

        mvc.perform(post("/members/21/enable").param("mode", "fail-inside"))
                .andExpect(status().isInternalServerError());

        assertThat(onlyFailure().event()).isEqualTo("member.enabled");
    }

    // ── Flood control ────────────────────────────────────────────────────

    @Test
    void aThousandRefusalsFromOneUserAreAHandfulOfRowsAndAnotherOrganizationIsStillHeard() throws Exception {
        io.micrometer.core.instrument.simple.SimpleMeterRegistry metrics =
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
        io.micrometer.core.instrument.Metrics.addRegistry(metrics);
        try {
            as("VIEWER");
            for (int i = 0; i < 1000; i++) {
                mvc.perform(post("/members/21/disable")).andExpect(status().isForbidden());
            }
            assertThat(failures()).as("a repeat is written once a minute").hasSize(1);

            for (int i = 0; i < 1000; i++) {
                mvc.perform(post("/members/" + (100 + i) + "/disable")).andExpect(status().isForbidden());
            }
            assertThat(failures()).as("one actor: at most %d rows a minute", AuditFailures.ACTOR_ROWS_PER_MINUTE)
                    .hasSize(AuditFailures.ACTOR_ROWS_PER_MINUTE);

            GatewayRequestContext.set(6, String.valueOf(OTHER_ORG_ID), "req-other", null);
            mvc.perform(post("/members/21/disable")).andExpect(status().isForbidden());
            List<AuditEventRow> rows = failures();
            assertThat(rows.get(rows.size() - 1).organizationId()).as("an unrelated organization still writes")
                    .isEqualTo(OTHER_ORG_ID);
            assertThat(metrics.find("certping.audit.throttled").tag("event", "member.disabled").counter().count())
                    .isEqualTo(2000 - AuditFailures.ACTOR_ROWS_PER_MINUTE);
        } finally {
            io.micrometer.core.instrument.Metrics.removeRegistry(metrics);
        }
    }

    @Test
    void oneOrganizationCannotTakeMoreThanItsShareOfTheQueue() throws Exception {
        as("VIEWER");
        for (int user = 0; user < 40; user++) {
            GatewayRequestContext.set(1000 + user, String.valueOf(ORG_ID), "req-" + user, null);
            for (int target = 0; target < AuditFailures.ACTOR_ROWS_PER_MINUTE; target++) {
                mvc.perform(post("/members/" + target + "/disable")).andExpect(status().isForbidden());
            }
        }
        assertThat(failures()).as("40 users x 30 rows, capped per organization")
                .hasSize(AuditFailures.ORGANIZATION_ROWS_PER_MINUTE);

        GatewayRequestContext.set(6, String.valueOf(OTHER_ORG_ID), "req-other", null);
        mvc.perform(post("/members/21/disable")).andExpect(status().isForbidden());
        assertThat(failures()).hasSize(AuditFailures.ORGANIZATION_ROWS_PER_MINUTE + 1);
    }

    private List<AuditEventRow> failures() {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, org.mockito.Mockito.atLeast(0)).recordFailure(rows.capture());
        return rows.getAllValues();
    }
}
