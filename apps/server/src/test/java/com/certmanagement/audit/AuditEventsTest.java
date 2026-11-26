// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.util.MdcContextPropagator;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditEventsTest {

    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();

    @BeforeEach
    void countMetrics() {
        Metrics.addRegistry(metrics);
    }

    @AfterEach
    void clear() {
        Metrics.removeRegistry(metrics);
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @Test
    void aRequestRowCarriesTheUserTheirOrganizationAndWhereTheRequestCameFrom() {
        inRequest(7, "42", false);

        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_CREATED, AuditSubject.builder()
                .resourceRef("cred-xref-1").name("prod-azure").provider("Azure").build());

        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.event()).isEqualTo("credential.created");
        assertThat(row.category()).isEqualTo("CREDENTIALS");
        assertThat(row.featureKey()).isEqualTo("CREDENTIALS_MANAGEMENT");
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.actorType()).isEqualTo(AuditActorType.USER);
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.actorLabel()).as("snapshotted by the store").isNull();
        assertThat(row.actorStaff()).isFalse();
        assertThat(row.action()).isEqualTo("CREATE");
        assertThat(row.resourceType()).isEqualTo("CREDENTIAL");
        assertThat(row.resourceRef()).isEqualTo("cred-xref-1");
        assertThat(row.resourceName()).isEqualTo("prod-azure");
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(row.summary()).isEqualTo("Added the Azure credential 'prod-azure'");
        assertThat(row.ipAddress()).isEqualTo("203.0.113.9");
        assertThat(row.userAgent()).isEqualTo("Mozilla/5.0 test");
        assertThat(row.requestId()).isEqualTo("req-abc");
        assertThat(row.correlationId()).isEqualTo("corr-abc");
    }

    @Test
    void aFailureStoresTheReasonCodeAndTheFailureSentence() {
        inRequest(7, "42", false);

        AuditEventRow row = AuditEvents.failure(AuditEventType.CREDENTIAL_CREATED,
                AuditSubject.builder().name("prod-azure").provider("Azure").build(),
                AuditReason.of("AZURE_PERMISSION_DENIED"));

        assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(row.errorCode()).isEqualTo("AZURE_PERMISSION_DENIED");
        assertThat(row.summary()).isEqualTo("Could not add the Azure credential 'prod-azure'");
    }

    @Test
    void aMembersNameIsNeverStored() {
        inRequest(7, "42", false);

        AuditEventRow row = AuditEvents.success(AuditEventType.MEMBER_CREATED,
                AuditSubject.builder().resourceId(99L).name("Bob Example").build());

        assertThat(row.summary()).isEqualTo("Added a member");
        assertThat(row.resourceName()).isNull();
        assertThat(row.resourceId()).isEqualTo(99L);
        assertThat(AuditEventType.MEMBER_CREATED.summary(AuditSubject.builder().name("Bob Example").build()))
                .as("rendered again when read").isEqualTo("Added Bob Example");
    }

    @Test
    void attributesOffTheAllowListAreDropped() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("credentialType", "DNS");
        attributes.put("email", "bob@example.com");

        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().name("x").attributes(attributes).build());

        assertThat(row.details().attributes()).containsExactly(Map.entry("credentialType", "DNS"));
    }

    @Test
    void aSuperAdminsActionIsStaffInAnyTrailAndAMembersInNone() {
        inRequest(1, "1", true);

        AuditEventRow inTheirOwn = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED, AuditSubject.NONE);
        AuditEventRow inACustomers = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().organizationId(42L).build());

        assertThat(inTheirOwn.actorStaff()).as("staffness is the action's, not the trail's").isTrue();
        assertThat(inACustomers.organizationId()).isEqualTo(42L);
        assertThat(inACustomers.actorStaff()).isTrue();

        SecurityContextHolder.clearContext();
        inRequest(2, "1", false);
        assertThat(AuditEvents.success(AuditEventType.CREDENTIAL_DELETED, AuditSubject.NONE).actorStaff()).isFalse();
        assertThat(AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().organizationId(42L).build()).actorStaff())
                .as("a member is never staff, whatever trail the row lands in").isFalse();

        inRequest(3, null, false);
        assertThat(AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().organizationId(42L).build()).actorStaff())
                .as("an account acting for no organization (accepting an invitation, say) is itself")
                .isFalse();
    }

    @Test
    void aSystemScopeActsAsCertPingWithoutAClientAndNestsBack() {
        inRequest(7, "42", false);
        MDC.put("correlationId", "corr-job");

        try (AuditScope outer = AuditScope.system("trigger-renewals", 42L)) {
            AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED, AuditSubject.NONE);
            assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(row.actorUserId()).isNull();
            assertThat(row.actorLabel()).isEqualTo("CertPing (automatic)");
            assertThat(row.actorJob()).isEqualTo("trigger-renewals");
            assertThat(row.organizationId()).isEqualTo(42L);
            assertThat(row.ipAddress()).isNull();
            assertThat(row.userAgent()).isNull();
            assertThat(row.correlationId()).isEqualTo("corr-job");

            try (AuditScope inner = AuditScope.system("audit-partitions", null, "corr-inner")) {
                AuditEventRow platform = AuditEvents.internal(AuditEventType.AUDIT_PARTITION_CREATED,
                        AuditSubject.builder().name("audit_events_2026_11").build());
                assertThat(platform.organizationId()).isNull();
                assertThat(platform.actorJob()).isEqualTo("audit-partitions");
                assertThat(platform.correlationId()).isEqualTo("corr-inner");
                assertThat(platform.visibility()).isEqualTo(AuditVisibility.INTERNAL);
            }
            assertThat(AuditContext.actor().job()).isEqualTo("trigger-renewals");
        }
        assertThat(AuditContext.actor().type()).isEqualTo(AuditActorType.USER);
    }

    @Test
    void aRowWrittenOnAnMdcDecoratedWorkerCarriesTheRequestsIdsButNoClientAddress() throws Exception {
        inRequest(7, "42", false);
        AtomicReference<AuditEventRow> row = new AtomicReference<>();
        Thread worker = new Thread(MdcContextPropagator.wrap(() -> row.set(AuditEvents.success(
                AuditEventType.CREDENTIAL_DELETED, AuditSubject.builder().organizationId(42L).build()))));

        worker.start();
        worker.join();

        assertThat(row.get().requestId()).isEqualTo("req-abc");
        assertThat(row.get().correlationId()).isEqualTo("corr-abc");
        assertThat(row.get().ipAddress()).isNull();
    }

    @Test
    void outsideARequestAndAScopeTheActorIsAnonymous() {
        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().organizationId(42L).build());

        assertThat(row.actorType()).isEqualTo(AuditActorType.ANONYMOUS);
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.requestId()).isNull();
    }

    @Test
    void aCustomerRowWithNoOrganizationIsKeptAsInternalAndCounted() {
        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().name("prod-azure").build());

        assertThat(row.organizationId()).isNull();
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.event()).isEqualTo("credential.deleted");
        assertThat(row.summary()).isEqualTo("Deleted the credential 'prod-azure'");
        assertThat(metrics.get(AuditEvents.DOWNGRADED_METRIC).tag("reason", "no_org")
                .tag("event", "credential.deleted").counter().count()).isEqualTo(1);
    }

    @Test
    void changesOffTheAllowListAreDroppedAndCounted() {
        inRequest(7, "42", false);

        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_UPDATED, AuditSubject.builder()
                .name("prod-azure")
                .changes(List.of(new AuditChange("name", "old", "new"), new AuditChange("keyVaultUri", "a", "b")))
                .build());

        assertThat(row.details().changes()).containsExactly(new AuditChange("name", "old", "new"));
        assertThat(rejected("changes", "credential.updated")).isEqualTo(1);
    }

    @Test
    void aMembersPersonalFieldsAreKeptByNameOnly() {
        inRequest(7, "42", false);

        AuditEventRow row = AuditEvents.success(AuditEventType.MEMBER_CREATED, AuditSubject.builder()
                .resourceRef("99")
                .changes(List.of(new AuditChange("email", null, "bob@example.com"),
                        new AuditChange("name", null, "Bob Example"),
                        new AuditChange("roles", null, "VIEWER"),
                        new AuditChange("phone", null, "+1 555 0100")))
                .build());

        assertThat(row.details().changes()).containsExactly(new AuditChange("email", null, null),
                new AuditChange("name", null, null), new AuditChange("roles", null, "VIEWER"));
        assertThat(row.resourceRef()).isEqualTo("99");
        assertThat(rejected("changes", "member.created")).isEqualTo(1);
    }

    @Test
    void aMemberTargetReferencedByAnythingButItsIdLosesTheReferenceNotTheRow() {
        inRequest(7, "42", false);

        AuditEventRow byEmail = AuditEvents.success(AuditEventType.MEMBER_CREATED,
                AuditSubject.builder().resourceId(99L).resourceRef("bob@example.com").build());
        AuditEventRow credential = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().resourceRef("cred-xref-1").build());

        assertThat(byEmail.resourceRef()).isNull();
        assertThat(byEmail.resourceId()).isEqualTo(99L);
        assertThat(byEmail.summary()).isEqualTo("Added a member");
        assertThat(rejected("resource_ref", "member.created")).isEqualTo(1);
        assertThat(credential.resourceRef()).as("other targets keep string refs").isEqualTo("cred-xref-1");
    }

    /**
     * The read side renders a member event's summary again from the live name. That only works if the
     * stored sentence is the template with "a member" in the name's place, and if nothing else the
     * template reads is missing from the row: whatever else it uses must come from allow-listed,
     * non-personal attributes.
     */
    @Test
    void memberSummariesRenderAgainFromTheStoredRow() {
        AuditSubject full = AuditSubject.builder().organizationId(42L).resourceId(99L).resourceRef("99")
                .name("Bob Example").provider("Azure").domain("example.com").count(3).format("PEM").enabled(true)
                .build();
        assertThat(List.of(AuditEventType.values())).filteredOn(AuditEventType::rendersTargetWhenRead).isNotEmpty()
                .allSatisfy(type -> {
                    AuditSubject storedInputs = AuditSubject.builder().attributes(attributesOnly(type, full)).build();
                    String storedSummary = type.summary(storedInputs);
                    String storedFailure = type.failure(storedInputs);
                    assertThat(storedSummary).contains(AuditEventType.STORED_MEMBER);
                    assertThat(type.summary(full)).isEqualTo(
                            storedSummary.replace(AuditEventType.STORED_MEMBER, "Bob Example"));
                    assertThat(type.failure(full)).isEqualTo(
                            storedFailure.replace(AuditEventType.STORED_MEMBER, "Bob Example"));
                    assertThat(type.allowedAttributes()).noneMatch(name -> AuditSanitizer.isSecretName(name)
                            || name.toLowerCase().matches(".*(email|name|phone|address|ip).*"));
                });
    }

    @Test
    void secretFieldsAreStoredByNameOnly() {
        inRequest(7, "42", false);

        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_UPDATED, AuditSubject.builder()
                .name("prod-azure")
                .changes(List.of(new AuditChange("clientSecret", "old-secret", "new-secret"),
                        new AuditChange("clientId", "a", "b")))
                .build());

        assertThat(row.details().changes()).containsExactly(new AuditChange("clientSecret", null, null),
                new AuditChange("clientId", "a", "b"));
    }

    /** A credential's pasted details, its secret store location and its scope are named, never valued. */
    @Test
    void aCredentialsDetailsLocationAndScopeAreNamedNeverValued() {
        inRequest(7, "42", false);
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("credentialType", "DNS");
        attributes.put("credJson", "{\"apiToken\":\"cf-live-token\"}");
        attributes.put("secretHandle", "https://example-vault-agent.vault.azure.net/secrets/org-42");

        AuditEventRow created = AuditEvents.success(AuditEventType.CREDENTIAL_CREATED,
                AuditSubject.builder().name("Prod DNS").provider("Cloudflare").attributes(attributes).build());
        AuditEventRow updated = AuditEvents.success(AuditEventType.CREDENTIAL_UPDATED, AuditSubject.builder()
                .changes(List.of(new AuditChange("credJson", null, "{\"apiToken\":\"new\"}"),
                        new AuditChange("secretHandle", "https://a.vault.azure.net/s/x", "https://b.vault.azure.net/s/y"),
                        new AuditChange("configJson", "{}", "{\"subscriptionId\":\"sub-1\"}")))
                .build());

        assertThat(created.summary()).isEqualTo("Added the Cloudflare DNS credential 'Prod DNS'");
        assertThat(created.details().attributes()).containsEntry("credentialType", "DNS")
                .containsEntry("credJson", null).containsEntry("secretHandle", null);
        assertThat(updated.details().changes()).containsExactly(new AuditChange("credJson", null, null),
                new AuditChange("secretHandle", null, null), new AuditChange("configJson", null, null));
    }

    /** No secret value is ever stored, not even redacted: a secret-looking name must be declared name-only. */
    @Test
    void everySecretLookingFieldInTheCatalogIsNameOnly() {
        assertThat(List.of(AuditEventType.values())).allSatisfy(type -> {
            java.util.Set<String> withValues = new java.util.HashSet<>(type.allowedChanges());
            withValues.addAll(type.allowedAttributes());
            assertThat(withValues).as(type.key()).noneMatch(AuditSanitizer::isSecretName);
            assertThat(type.nameOnly()).as(type.key()).noneMatch(withValues::contains);
        });
    }

    @Test
    void aSecretPastedIntoANameIsRedactedBeforeTheSentenceIsWritten() {
        inRequest(7, "42", false);
        String pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";

        AuditEventRow pemName = AuditEvents.success(AuditEventType.CREDENTIAL_CREATED,
                AuditSubject.builder().name(pem).provider("Azure").build());
        AuditEventRow jwtName = AuditEvents.failure(AuditEventType.CREDENTIAL_DELETED,
                AuditSubject.builder().name("token " + jwt).provider(jwt).build(), AuditReason.of("NOT_FOUND"));

        assertThat(pemName.resourceName()).isEqualTo(AuditSanitizer.REDACTED);
        assertThat(pemName.summary()).isEqualTo("Added the Azure credential '[REDACTED]'").doesNotContain("BEGIN");
        assertThat(jwtName.resourceName()).isEqualTo(AuditSanitizer.REDACTED);
        assertThat(jwtName.summary()).isEqualTo("Could not delete the [REDACTED] credential '[REDACTED]'")
                .doesNotContain("eyJ");
    }

    private static java.util.Map<String, String> attributesOnly(AuditEventType type, AuditSubject subject) {
        java.util.Map<String, String> kept = new LinkedHashMap<>(subject.attributes());
        kept.keySet().retainAll(type.allowedAttributes());
        return kept;
    }

    private double rejected(String field, String event) {
        return metrics.get(AuditEvents.FIELD_REJECTED_METRIC).tag("field", field).tag("event", event)
                .counter().count();
    }

    @Test
    void customerAndInternalEventsCannotBeMixedUp() {
        assertThatThrownBy(() -> AuditEvents.success(AuditEventType.AUDIT_PARTITION_CREATED, AuditSubject.NONE))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuditEvents.internal(AuditEventType.MEMBER_CREATED, AuditSubject.NONE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void everyEventHasAUniqueKeyAndSentencesForAnEmptySubject() {
        assertThat(List.of(AuditEventType.values())).allSatisfy(type -> {
            assertThat(AuditEventType.byKey(type.key())).contains(type);
            assertThat(type.summary(AuditSubject.NONE)).isNotBlank().doesNotContain("null");
            assertThat(type.failure(AuditSubject.NONE)).isNotBlank().doesNotContain("null");
            assertThat(type.key()).matches("^[a-z_]+\\.[a-z_]+$");
        });
        assertThat(AuditEventType.byKey("no.such_event")).isEmpty();
    }

    @Test
    void anInternalOnlyAttributeNeverReachesACustomerRow() {
        inRequest(7, "42", true);
        AuditSubject subject = AuditSubject.builder().organizationId(42L).name("DISCOVERY")
                .attributes(Map.of("level", "ORGANIZATION", "reason", "customer asked for a review")).build();

        assertThat(AuditEvents.success(AuditEventType.FEATURE_CHANGED, subject).details().attributes())
                .containsOnlyKeys("level");
        assertThat(AuditEvents.success(AuditEventType.FEATURE_OVERRIDE_REMOVED, subject).toString())
                .doesNotContain("asked for a review");
        assertThat(AuditEvents.platformOnly(AuditEventType.FEATURE_CHANGED, subject).details().attributes())
                .containsEntry("reason", "customer asked for a review");
    }

    @Test
    void everyInternalOnlyAttributeIsOneNoCustomerRowKeeps() {
        assertThat(AuditEventType.FEATURE_CHANGED.internalOnlyAttributes()).containsExactly("reason");
        assertThat(AuditEventType.FEATURE_OVERRIDE_REMOVED.internalOnlyAttributes()).containsExactly("reason");
        assertThat(List.of(AuditEventType.values())).allSatisfy(type -> assertThat(type.internalOnlyAttributes())
                .as("%s: an attribute is either shown to customers or internal-only", type.key())
                .noneMatch(type.allowedAttributes()::contains));
    }

    private static void inRequest(int userId, String organizationId, boolean superAdmin) {
        GatewayRequestContext.set(userId, organizationId, "req-abc", "user@example.com");
        RequestContextInterceptor.setCurrentRequestId("req-abc");
        RequestContextInterceptor.setCurrentCorrelationId("corr-abc");
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 test");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        if (superAdmin) {
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                    "admin", null, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
        }
    }
}
