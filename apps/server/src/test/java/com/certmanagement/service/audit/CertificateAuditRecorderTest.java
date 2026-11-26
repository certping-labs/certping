// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditContext;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every certificate and deployment event as the trail stores it: a member's request is the member's row, what the
 * agent reports is CertPing's with the requesting member's id and the message's correlation id, and a failure's
 * cause is its reason code only.
 */
class CertificateAuditRecorderTest {

    private static final long ORG = 42L;
    private static final int MEMBER = 7;

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-07T10:00:00Z"));
    private final Clock clock = new Clock() {
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now.get(); }
    };
    private final CredentialAuditRecorder credentialAudit = new CredentialAuditRecorder(recorder);
    private final CredentialReferenceRepository credentials = mock(CredentialReferenceRepository.class);
    private final CertificateAuditRecorder audit = new CertificateAuditRecorder(recorder, clock, credentialAudit,
            credentials);

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    // ── A member's requests ─────────────────────────────────────────────

    @Test
    void aMembersRequestsAreTheirRows() {
        GatewayRequestContext.set(MEMBER, String.valueOf(ORG), "req-1", "alice@acme.test");
        CertificateEntity cert = certificate("cert-1", "example.com");
        cert.setWildcard(true);
        cert.setSanDomains(new String[]{"example.com", "www.example.com"});

        audit.issueRequested(cert, 2);
        audit.manualIssueRequested(cert);
        audit.dnsValidationStarted(cert);
        audit.renewalRequested(cert);
        audit.revokeRequested(cert, "KEY_COMPROMISE");
        audit.deleted(cert, null, "ACTIVE");
        audit.convertedToAutomated(cert, "IMMEDIATE", "CONFIG_UPDATED_AND_RENEWAL_TRIGGERED", 1);
        audit.deploymentRequested(cert, "AZURE_KV");

        List<AuditEventRow> rows = recorded(8);
        verify(recorder, never()).recordIsolated(org.mockito.ArgumentMatchers.any());
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Requested a certificate for example.com from Let's Encrypt",
                "Started a manual issuance of a certificate for example.com from Let's Encrypt",
                "Confirmed the DNS records for example.com were added and started validation",
                "Requested renewal of the certificate for example.com",
                "Requested revocation of the certificate for example.com",
                "Deleted the certificate for example.com",
                "Switched the certificate for example.com to automatic renewal",
                "Started deploying the certificate for example.com to Azure Key Vault");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.actorType()).isEqualTo(AuditActorType.USER);
            assertThat(row.actorUserId()).isEqualTo(MEMBER);
            assertThat(row.organizationId()).isEqualTo(ORG);
            assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
            assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
            assertThat(row.resourceRef()).isEqualTo("cert-1");
            assertThat(row.resourceName()).isEqualTo("example.com");
        });
        assertThat(rows.get(0).details().attributes()).containsOnly(Map.entry("wildcard", "true"),
                Map.entry("sanDomains", "2"), Map.entry("deploymentTargets", "2"));
        assertThat(rows.get(0).featureKey()).isEqualTo(FeatureFlags.CERTIFICATE_ISSUANCE);
        assertThat(rows.get(0).category()).isEqualTo("CERTIFICATES");
        assertThat(rows.get(4).details().attributes()).containsOnly(Map.entry("revocationReason", "KEY_COMPROMISE"));
        assertThat(rows.get(5).featureKey()).as("certificate:delete is core").isNull();
        assertThat(rows.get(7).category()).isEqualTo("DEPLOYMENTS");
        assertThat(rows.get(7).resourceType()).isEqualTo("DEPLOYMENT");
        assertThat(rows.get(7).details().attributes()).containsOnly(Map.entry("targetType", "AZURE_KV"));
    }

    @Test
    void aRevocationReasonOutsideOurVocabularyIsLeftOut() {
        GatewayRequestContext.set(MEMBER, String.valueOf(ORG), "req-1", "alice@acme.test");

        audit.revokeRequested(certificate("cert-1", "example.com"), "because db01.internal said so; DROP TABLE");

        assertThat(recorded(1).get(0).details().attributes()).isEmpty();
    }

    // ── What the agent reports (CertPing, for the member) ───────────────

    @Test
    void anAgentResultIsCertPingsRowNamingTheMemberById() {
        CertificateEntity cert = certificate("cert-1", "example.com");
        cert.setValidTo(OffsetDateTime.parse("2027-01-05T00:00:00Z"));
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.AGENT_JOB, ORG, "corr-original")) {
            audit.issued(cert, MEMBER, null);
            audit.renewed(cert, "cert-0", MEMBER);
            audit.revoked(cert, MEMBER, "SUPERSEDED");
            audit.deploymentSucceeded(cert, "AWS_ACM", "MANUAL", MEMBER);
        }

        List<AuditEventRow> rows = isolated(4);
        verify(recorder, never()).record(org.mockito.ArgumentMatchers.any());
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Issued the certificate for example.com from Let's Encrypt",
                "Renewed the certificate for example.com from Let's Encrypt",
                "Revoked the certificate for example.com",
                "Deployed the certificate for example.com to AWS Certificate Manager");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(row.actorLabel()).isEqualTo(AuditContext.SYSTEM_LABEL).isEqualTo("CertPing (automatic)");
            assertThat(row.actorJob()).isEqualTo("agent-response");
            assertThat(row.actorUserId()).isNull();
            assertThat(row.correlationId()).isEqualTo("corr-original");
            assertThat(row.ipAddress()).isNull();
            assertThat(row.details().attributes()).containsEntry("requestedBy", "7");
        });
        assertThat(rows.get(1).details().attributes()).containsEntry("replaces", "cert-0")
                .containsEntry("validTo", "2027-01-05T00:00Z");
        assertThat(rows.get(3).details().attributes()).containsOnly(Map.entry("requestedBy", "7"),
                Map.entry("targetType", "AWS_ACM"), Map.entry("flow", "MANUAL"));
    }

    @Test
    void anAgentFailureCarriesItsCodeWithRetryGiveUpUnwrapped() {
        CertificateEntity cert = certificate("cert-1", "example.com");
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.AGENT_JOB, ORG, "corr-original")) {
            audit.issueFailed(cert, AuditReason.fromAgent("RETRY_GIVE_UP", "DNS_AUTH_FAILED"), MEMBER);
            audit.renewalFailed(cert, AuditReason.fromAgent("ACME_RATE_LIMITED", null), null);
            audit.revocationFailed(cert, AuditReason.fromAgent("REVOCATION_UNAUTHORIZED", null), MEMBER);
            audit.deploymentFailed(cert, "AZURE_KV", "AUTO_POST_RENEWAL",
                    AuditReason.fromAgent("DEPLOY_AZURE_KV_IMPORT_FAILED", null), null);
            audit.deploymentFailed(cert, "GCP_CERT_MANAGER", null,
                    AuditReason.fromAgent("RETRY_GIVE_UP", "DEPLOY_GCP_SSL_CERT_FAILED"), MEMBER);
        }

        List<AuditEventRow> rows = isolated(5);
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Issuing the certificate for example.com failed",
                "Renewing the certificate for example.com failed",
                "Revoking the certificate for example.com failed",
                "Deploying the certificate for example.com to Azure Key Vault failed",
                "Deploying the certificate for example.com to Google Cloud Certificate Manager failed");
        assertThat(rows).extracting(AuditEventRow::errorCode).containsExactly("DNS_AUTH_FAILED", "ACME_RATE_LIMITED",
                "REVOCATION_UNAUTHORIZED", "DEPLOY_AZURE_KV_IMPORT_FAILED", "DEPLOY_GCP_SSL_CERT_FAILED");
        assertThat(rows).extracting(AuditEventRow::event).containsExactly("certificate.issued", "certificate.renewed",
                "certificate.revoked", "deployment.failed", "deployment.failed");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
            assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
        });
        assertThat(rows.get(1).details().attributes()).as("a renewal CertPing started names no member").isEmpty();
    }

    // ── CertPing's own work ─────────────────────────────────────────────

    @Test
    void certPingsOwnWorkIsItsRowsUnderTheJob() {
        CertificateEntity cert = certificate("cert-1", "example.com");
        cert.setValidTo(OffsetDateTime.parse("2026-10-01T00:00:00Z"));
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.RENEWAL_JOB, null, "corr-drain")) {
            audit.autoRenewalStarted(cert, null);
            audit.autoRenewalSkipped(cert, List.of(FeatureFlags.CERTIFICATE_RENEWAL, FeatureFlags.CA_LETS_ENCRYPT),
                    "AUTO_POST_RENEWAL");
            audit.autoDeploySkipped(cert, "AUTO_POST_ISSUANCE");
        }
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.EXPIRY_JOB, ORG)) {
            audit.expired(cert);
        }
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.CLEANUP_JOB, ORG)) {
            audit.deleted(cert, CertificateAuditRecorder.SOURCE_EXPIRY_CLEANUP, "EXPIRED");
        }

        List<AuditEventRow> rows = isolated(5);
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Started renewing the certificate for example.com automatically",
                "Skipped renewing the certificate for example.com automatically because the features "
                        + "'Certificate Renewal' and 'Let's Encrypt' are off",
                "Skipped deploying the certificate for example.com automatically because the feature "
                        + "'Certificate Deployment' is off",
                "The certificate for example.com expired",
                "Deleted the certificate for example.com");
        assertThat(rows).extracting(AuditEventRow::actorJob).containsExactly("trigger-renewals", "trigger-renewals",
                "trigger-renewals", "mark-expired-certs", "expiry-cleanup");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(row.organizationId()).as("the certificate's trail, whatever the job's").isEqualTo(ORG);
        });
        assertThat(rows.get(1).errorCode()).isEqualTo("FEATURE_OFF");
        assertThat(rows.get(2).errorCode()).isEqualTo("FEATURE_OFF");
        assertThat(rows.get(4).details().attributes()).containsOnly(Map.entry("source", "EXPIRY_CLEANUP"),
                Map.entry("status", "EXPIRED"));
    }

    @Test
    void aRenewalHeldByAnExpiredCertPingDnsKey_saysWhenTheKeyExpired() {
        CertificateEntity cert = certificate("cert-1", "example.com");
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.RENEWAL_JOB, null)) {
            audit.autoRenewalHeldByExpiredDnsKey(cert, Instant.parse("2026-10-01T23:30:00Z"));
        }

        AuditEventRow row = isolated(1).get(0);
        assertThat(row.summary()).isEqualTo("Skipped renewing the certificate for example.com automatically because "
                + "its CertPing DNS key expired on 2026-10-01 (UTC)");
        assertThat(row.errorCode()).isEqualTo("DNS_KEY_EXPIRED");
        assertThat(row.details().attributes()).containsEntry("dnsKeyExpiredOn", "2026-10-01");
    }

    @Test
    void theRenewalJobWritesTheSameSkipOnceADayAcrossPods() {
        CertificateEntity cert = certificate("cert-1", "example.com");
        // The window is the trail itself: a skip already written in the last day, by any pod, holds the next back.
        when(recorder.recordedSince(eq(ORG), eq(AuditEventType.CERTIFICATE_AUTO_RENEWAL_SKIPPED), eq("cert-1"),
                eq(now.get().minus(Duration.ofHours(24))))).thenReturn(false, true);
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.RENEWAL_JOB, null)) {
            audit.autoRenewalSkippedByJob(cert, FeatureFlags.CA_DIGICERT);
            audit.autoRenewalSkippedByJob(cert, FeatureFlags.CA_DIGICERT);
        }

        assertThat(isolated(1)).extracting(AuditEventRow::summary).containsExactly(
                "Skipped renewing the certificate for example.com automatically because the feature 'DigiCert' is off");
    }

    // ── Rows with no transaction open (the async writer) ────────────────

    @Test
    void anAutomaticDeploysTargetsAreQueuedEachWithItsOutcome() {
        CertificateEntity cert = certificate("cert-1", "example.com");
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.AGENT_JOB, ORG, "corr-1")) {
            audit.autoDeployStarted(cert, "AZURE_KV", "AUTO_POST_ISSUANCE");
            audit.deploymentDispatchFailed(cert, "AWS_ACM", "AUTO_POST_ISSUANCE", AuditReasons.SERVICE_UNAVAILABLE);
        }

        ArgumentCaptor<AuditEventRow> started = ArgumentCaptor.forClass(AuditEventRow.class);
        ArgumentCaptor<AuditEventRow> failed = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordAsync(started.capture());
        verify(recorder).recordFailure(failed.capture());
        verify(recorder, never()).record(org.mockito.ArgumentMatchers.any());
        assertThat(started.getValue().summary())
                .isEqualTo("Started deploying the certificate for example.com to Azure Key Vault automatically");
        assertThat(failed.getValue().summary())
                .isEqualTo("Deploying the certificate for example.com to AWS Certificate Manager failed");
        assertThat(failed.getValue().errorCode()).isEqualTo("SERVICE_UNAVAILABLE");
    }

    @Test
    void aRowThatCannotBeQueuedNeverStopsTheTargetsAfterIt() {
        doThrow(new IllegalStateException("writer closed")).when(recorder)
                .recordAsync(org.mockito.ArgumentMatchers.any());

        audit.autoDeployStarted(certificate("cert-1", "example.com"), "AZURE_KV", "AUTO_POST_ISSUANCE");
        audit.autoDeployStarted(certificate("cert-2", "example.com"), "AZURE_KV", "AUTO_POST_ISSUANCE");

        verify(recorder, times(2)).recordAsync(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void anUnknownTargetTypeOrCertificateWithoutADomainStillReads() {
        GatewayRequestContext.set(MEMBER, String.valueOf(ORG), "req-1", "alice@acme.test");
        CertificateEntity bare = CertificateEntity.builder().certificateXref("cert-9")
                .userDomainCert(UserDomainCertEntity.builder().organizationId(ORG).build()).build();

        audit.deploymentRequested(bare, "SOMETHING_NEW");

        AuditEventRow row = recorded(1).get(0);
        assertThat(row.summary()).isEqualTo("Started deploying the certificate");
        assertThat(row.details().attributes()).containsOnly(Map.entry("targetType", "SOMETHING_NEW"));
    }

    // ── Deployment targets an issuance, renewal or conversion replaced ──

    @Test
    void replacedDeploymentTargetsAreOneRowPerTargetThatChanged() {
        GatewayRequestContext.set(MEMBER, String.valueOf(ORG), "req-1", "alice@acme.test");
        when(credentials.findByCredentialXrefIn(org.mockito.ArgumentMatchers.anyCollection())).thenReturn(List.of(
                CredentialReferenceEntity.builder().id(5L).organizationId(ORG).credentialXref("cred-kv")
                        .provider("AZURE_KV").type("DEPLOYMENT").description("prod vault").build(),
                CredentialReferenceEntity.builder().id(6L).organizationId(99L).credentialXref("cred-other")
                        .provider("AWS_ACM").type("DEPLOYMENT").description("someone else's").build()));

        audit.deploymentTargetsReplaced(ORG, "example.com", List.of("cred-old", "cred-keep"),
                List.of("cred-keep", "cred-kv", "cred-other"));
        audit.deploymentTargetsReplaced(ORG, "example.com", List.of("cred-keep"), List.of("cred-keep"));

        List<AuditEventRow> rows = recorded(3);
        assertThat(rows).extracting(AuditEventRow::event).containsExactly("deployment_target.added",
                "deployment_target.added", "deployment_target.removed");
        assertThat(rows.get(0).summary())
                .isEqualTo("Added the Azure Key Vault deployment target 'prod vault' for example.com");
        assertThat(rows.get(1).resourceRef()).as("another organization's credential is named by reference only")
                .isEqualTo("cred-other");
        assertThat(rows.get(1).toString()).doesNotContain("someone else");
        assertThat(rows.get(2).resourceRef()).isEqualTo("cred-old");
        assertThat(rows).allSatisfy(row -> assertThat(row.actorUserId()).isEqualTo(MEMBER));
        verify(credentials, times(1)).findByCredentialXrefIn(org.mockito.ArgumentMatchers.anyCollection());
    }

    /** CertPing's rows: written isolated, so a row the database refuses never rolls back its change. */
    private List<AuditEventRow> isolated(int rows) {
        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, times(rows)).recordIsolated(captor.capture());
        return captor.getAllValues();
    }

    /** A member's rows: written with their request, which fails when its row cannot be. */
    private List<AuditEventRow> recorded(int rows) {
        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, times(rows)).record(captor.capture());
        return captor.getAllValues();
    }

    static CertificateEntity certificate(String xref, String domain) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder().id(2L).organizationId(ORG).domain(domain).build();
        return CertificateEntity.builder().id(9L).certificateXref(xref).userDomainCertId(2L).userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT).status("ACTIVE").build();
    }
}
