// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditContext;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DiscoveryConfigEntity;
import com.certmanagement.entity.DiscoveryScanEntity;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The discovery rows as they are stored: a member's scan carries the member, the target in words and the
 * credential's name; a scan that could not start is a failure row through the async writer; what became of a scan
 * is CertPing's row with the job named and no client; and the agent's detail text never reaches a row, only its
 * code.
 */
class DiscoveryAuditRecorderTest {

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final DiscoveryAuditRecorder discovery = new DiscoveryAuditRecorder(recorder);

    @BeforeEach
    void inAMembersRequest() {
        GatewayRequestContext.set(7, "42", "req-1", "jane@acme.test");
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
    }

    @Test
    void aStartedScanNamesTheTargetAndCredentialAndIsReferencedByTheScan() {
        discovery.scanStarted(config(), credential(), "scan-1", DiscoveryAuditRecorder.Trigger.NEW);

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("discovery.scan_started");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.category()).isEqualTo("DISCOVERY");
        assertThat(row.featureKey()).isEqualTo("DISCOVERY");
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.resourceId()).isEqualTo(5L);
        assertThat(row.resourceRef()).isEqualTo("scan-1");
        assertThat(row.summary())
                .isEqualTo("Started a certificate discovery scan of Kubernetes with the credential 'Prod cluster'");
        assertThat(row.details().attributes()).containsEntry("targetType", "KUBERNETES_SECRETS")
                .containsEntry("trigger", "NEW");
        assertThat(row.toString()).doesNotContain("example-vault").doesNotContain("vault.azure.net");
    }

    @Test
    void aSavedConfigurationThatCouldNotStartIsAFailureThroughTheAsyncWriter() {
        discovery.scanNotStarted(config(), DiscoveryAuditRecorder.Trigger.ALL_SAVED,
                DiscoveryAuditRecorder.CREDENTIAL_NOT_ACTIVE);

        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordFailure(captor.capture());
        verify(recorder, never()).record(org.mockito.ArgumentMatchers.any());
        AuditEventRow row = captor.getValue();
        assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(row.errorCode()).isEqualTo("CREDENTIAL_NOT_ACTIVE");
        assertThat(row.summary()).isEqualTo("Could not start a certificate discovery scan of Kubernetes");
        assertThat(row.details().attributes()).containsEntry("trigger", "ALL_SAVED");
    }

    @Test
    void whatBecameOfAScanIsCertPingsRowWithTheJobAndNoClient() {
        DiscoveryScanEntity scan = scan();
        scan.setReportedTotalCerts(12);
        discovery.scanCompleted(scan);
        discovery.scanFailed(scan, DiscoveryAuditRecorder.agentReason("DISCOVERY_K8S_SECRET_LIST_FAILED"));
        discovery.scanFailed(scan, DiscoveryAuditRecorder.NOT_PICKED_UP);
        discovery.scanCancelled(scan);

        List<AuditEventRow> rows = all();
        assertThat(rows).extracting(AuditEventRow::event).containsExactly("discovery.scan_completed",
                "discovery.scan_failed", "discovery.scan_failed", "discovery.scans_cancelled");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(row.actorJob()).isEqualTo(DiscoveryAuditRecorder.JOB);
            assertThat(row.actorLabel()).isEqualTo(AuditContext.SYSTEM_LABEL);
            assertThat(row.ipAddress()).isNull();
            assertThat(row.organizationId()).isEqualTo(42L);
            assertThat(row.resourceRef()).isEqualTo("scan-1");
        });
        assertThat(rows.get(0).summary())
                .isEqualTo("Finished a certificate discovery scan of AWS Certificate Manager and found 12 certificates");
        assertThat(rows.get(1).errorCode()).isEqualTo("DISCOVERY_K8S_SECRET_LIST_FAILED");
        assertThat(rows.get(1).summary()).isEqualTo("The certificate discovery scan of AWS Certificate Manager failed");
        assertThat(rows.get(2).errorCode()).isEqualTo("DISCOVERY_NOT_PICKED_UP");
        assertThat(rows.get(3).summary()).isEqualTo(
                "Stopped 1 discovery scan of AWS Certificate Manager because certificate discovery is turned off");
        assertThat(rows.get(3).details().attributes()).containsEntry("cause", "FEATURE_OFF");
        // Back in the member's request once the system scope closed.
        assertThat(AuditContext.actor().userId()).isEqualTo(7);
        // CertPing's rows about the agent's work never fail the transaction storing the agent's result.
        verify(recorder, org.mockito.Mockito.times(4)).recordIsolated(org.mockito.ArgumentMatchers.any());
        verify(recorder, never()).record(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void anAgentFailureIsStoredByItsCodeNeverItsText() {
        assertThat(DiscoveryAuditRecorder.agentReason(null).code()).isEqualTo("DISCOVERY_FAILED");
        assertThat(DiscoveryAuditRecorder.agentReason("  ").code()).isEqualTo("DISCOVERY_FAILED");
        assertThat(DiscoveryAuditRecorder.agentReason("list secrets failed: HTTP 403 namespace=prod"))
                .isEqualTo(AuditReason.INTERNAL_ERROR);
        assertThat(DiscoveryAuditRecorder.agentReason("DISCOVERY_FAILED").message(null))
                .doesNotContain("DISCOVERY_FAILED").isNotBlank();
        assertThat(DiscoveryAuditRecorder.NOT_PICKED_UP.message(null)).doesNotContain("NOT_PICKED_UP");
    }

    @Test
    void aDeletedConfigurationIsTheMembersRow() {
        discovery.configDeleted(config());

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("discovery.config_deleted");
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.summary()).isEqualTo("Deleted the discovery configuration for Kubernetes");
    }

    private static DiscoveryConfigEntity config() {
        return DiscoveryConfigEntity.builder().id(5L).organizationId(42L).targetType("KUBERNETES_SECRETS")
                .credentialXref("cred-k8s").build();
    }

    private static CredentialReferenceEntity credential() {
        return CredentialReferenceEntity.builder().id(9L).credentialXref("cred-k8s").organizationId(42L)
                .type("DEPLOYMENT").provider("KUBERNETES_SECRETS").description("Prod cluster")
                .secretHandle("https://example-vault-agent.vault.azure.net/secrets/k8s").status("ACTIVE").build();
    }

    private static DiscoveryScanEntity scan() {
        return DiscoveryScanEntity.builder().requestId("scan-1").organizationId(42L).targetType("AWS_ACM")
                .credentialXref("cred-acm").build();
    }

    private AuditEventRow recorded() {
        List<AuditEventRow> rows = all();
        assertThat(rows).hasSize(1);
        return rows.get(0);
    }

    /** Every row written in the change's transaction, by {@code record} or {@code recordIsolated}. */
    private List<AuditEventRow> all() {
        List<AuditEventRow> rows = org.mockito.Mockito.mockingDetails(recorder).getInvocations().stream()
                .filter(call -> call.getMethod().getName().equals("record")
                        || call.getMethod().getName().equals("recordIsolated"))
                .map(call -> (AuditEventRow) call.getArgument(0)).toList();
        assertThat(rows).as("rows written in the change's transaction").isNotEmpty();
        return rows;
    }
}
