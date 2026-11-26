// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.entity.DiscoveredCertObservationEntity;
import com.certmanagement.entity.DiscoveryInventoryStatus;
import com.certmanagement.entity.DiscoveryObservationStatus;
import com.certmanagement.entity.DiscoveryScanEntity;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryReconciliationServiceTest {

    @Mock private DiscoveredCertObservationRepository observationRepository;
    @Mock private DiscoveredCertRepository discoveredCertRepository;

    private DiscoveryReconciliationService service;

    @BeforeEach
    void setUp() {
        service = new DiscoveryReconciliationService(observationRepository, discoveredCertRepository);
    }

    @Test
    void reconcile_marksUnseenExactScopeMissingAndRetiresPreviousScopes() {
        DiscoveryScanEntity scan = DiscoveryScanEntity.builder()
                .requestId("req-1")
                .organizationId(42L)
                .targetType("KUBERNETES_SECRETS")
                .credentialXref("cred-1")
                .scopeKey("scope-1")
                .build();
        DiscoveredCertObservationEntity unseen = observation(10L, "scope-1", "old-req");
        DiscoveredCertObservationEntity seen = observation(11L, "scope-1", "req-1");
        DiscoveredCertObservationEntity oldScope = observation(12L, "old-scope", "older-req");
        DiscoveredCertEntity missing = certificate(10L);
        DiscoveredCertEntity stillPresent = certificate(12L);
        when(observationRepository.findAllByScopeKey("scope-1")).thenReturn(List.of(unseen, seen));
        when(observationRepository.findAllByOrganizationIdAndTargetTypeAndCredentialXrefAndScopeKeyNot(
                42L, "KUBERNETES_SECRETS", "cred-1", "scope-1"))
                .thenReturn(List.of(oldScope));
        when(observationRepository.findCertificateIdsWithStatus(any(), any()))
                .thenReturn(Set.of(12L), Set.of(10L), Set.of(12L));
        when(discoveredCertRepository.findAllById(any())).thenReturn(List.of(missing, stillPresent));

        service.reconcile(scan, OffsetDateTime.parse("2026-06-24T08:02:00Z"));

        assertThat(unseen.getStatus()).isEqualTo(DiscoveryObservationStatus.MISSING);
        assertThat(unseen.getMissingSince()).isNotNull();
        assertThat(seen.getStatus()).isEqualTo(DiscoveryObservationStatus.PRESENT);
        assertThat(oldScope.getStatus()).isEqualTo(DiscoveryObservationStatus.OUT_OF_SCOPE);
        assertThat(missing.getInventoryStatus()).isEqualTo(DiscoveryInventoryStatus.MISSING);
        assertThat(stillPresent.getInventoryStatus()).isEqualTo(DiscoveryInventoryStatus.PRESENT);
    }

    @Test
    void reconcile_marksPurelyOutOfScopeCertificateUnknownInsteadOfMissing() {
        DiscoveryScanEntity scan = DiscoveryScanEntity.builder()
                .requestId("req-1")
                .organizationId(42L)
                .targetType("KUBERNETES_SECRETS")
                .credentialXref("cred-1")
                .scopeKey("scope-1")
                .build();
        DiscoveredCertObservationEntity oldScope = observation(12L, "old-scope", "older-req");
        DiscoveredCertEntity certificate = certificate(12L);
        when(observationRepository.findAllByScopeKey("scope-1")).thenReturn(List.of());
        when(observationRepository.findAllByOrganizationIdAndTargetTypeAndCredentialXrefAndScopeKeyNot(
                42L, "KUBERNETES_SECRETS", "cred-1", "scope-1"))
                .thenReturn(List.of(oldScope));
        when(observationRepository.findCertificateIdsWithStatus(any(), any()))
                .thenReturn(Set.of(), Set.of(), Set.of(12L));
        when(discoveredCertRepository.findAllById(any())).thenReturn(List.of(certificate));

        service.reconcile(scan, OffsetDateTime.parse("2026-06-24T08:02:00Z"));

        assertThat(oldScope.getStatus()).isEqualTo(DiscoveryObservationStatus.OUT_OF_SCOPE);
        assertThat(certificate.getInventoryStatus()).isEqualTo(DiscoveryInventoryStatus.UNKNOWN);
        assertThat(certificate.getMissingSince()).isNull();
    }

    /** One AWS account failed; its certificates the scan did not see stay PRESENT, the others go MISSING. */
    @Test
    void reconcile_leavesCertificatesInAFailedScopeUnchanged() {
        DiscoveryScanEntity scan = DiscoveryScanEntity.builder()
                .requestId("req-1").organizationId(42L).targetType("AWS_ORGANIZATION_ACM")
                .credentialXref("cred-1").scopeKey("scope-1").build();
        DiscoveredCertObservationEntity failedAccount = observation(20L, "scope-1", "old-req");
        DiscoveredCertObservationEntity failedRegion = observation(21L, "scope-1", "old-req");
        DiscoveredCertObservationEntity readAccount = observation(22L, "scope-1", "old-req");
        DiscoveredCertObservationEntity seen = observation(23L, "scope-1", "req-1");
        DiscoveredCertEntity inFailedAccount = certificate(20L, "arn:aws:acm:us-east-1:111111111111:certificate/a");
        DiscoveredCertEntity inFailedRegion = certificate(21L, "arn:aws:acm:eu-west-1:333333333333:certificate/b");
        DiscoveredCertEntity reallyGone = certificate(22L, "arn:aws:acm:us-east-1:222222222222:certificate/c");
        when(observationRepository.findAllByScopeKey("scope-1"))
                .thenReturn(List.of(failedAccount, failedRegion, readAccount, seen));
        when(observationRepository.findAllByOrganizationIdAndTargetTypeAndCredentialXrefAndScopeKeyNot(
                42L, "AWS_ORGANIZATION_ACM", "cred-1", "scope-1")).thenReturn(List.of());
        when(discoveredCertRepository.findAllById(any()))
                .thenReturn(List.of(inFailedAccount, inFailedRegion, reallyGone), List.of(reallyGone));
        when(observationRepository.findCertificateIdsWithStatus(any(), any()))
                .thenReturn(Set.of(), Set.of(22L), Set.of());

        service.reconcile(scan, OffsetDateTime.parse("2026-10-30T08:00:00Z"), List.of(
                failed("AWS_ACCOUNT", "111111111111"),
                failed("AWS_REGION", "333333333333/eu-west-1")));

        assertThat(failedAccount.getStatus()).isEqualTo(DiscoveryObservationStatus.PRESENT);
        assertThat(failedAccount.getMissingSince()).isNull();
        assertThat(failedRegion.getStatus()).isEqualTo(DiscoveryObservationStatus.PRESENT);
        assertThat(readAccount.getStatus()).isEqualTo(DiscoveryObservationStatus.MISSING);
        assertThat(seen.getStatus()).isEqualTo(DiscoveryObservationStatus.PRESENT);
        assertThat(reallyGone.getInventoryStatus()).isEqualTo(DiscoveryInventoryStatus.MISSING);
        assertThat(inFailedAccount.getInventoryStatus()).isEqualTo(DiscoveryInventoryStatus.PRESENT);
    }

    @Test
    void reconcile_leavesAFailedVaultOrNamespaceUnchanged() {
        DiscoveryScanEntity scan = DiscoveryScanEntity.builder()
                .requestId("req-2").organizationId(42L).targetType("KUBERNETES_SECRETS")
                .credentialXref("cred-2").scopeKey("scope-2").build();
        DiscoveredCertObservationEntity forbidden = observation(30L, "scope-2", "old-req");
        DiscoveredCertObservationEntity readable = observation(31L, "scope-2", "old-req");
        when(observationRepository.findAllByScopeKey("scope-2")).thenReturn(List.of(forbidden, readable));
        when(observationRepository.findAllByOrganizationIdAndTargetTypeAndCredentialXrefAndScopeKeyNot(
                42L, "KUBERNETES_SECRETS", "cred-2", "scope-2")).thenReturn(List.of());
        when(discoveredCertRepository.findAllById(any())).thenReturn(List.of(
                certificate(30L, "k8s://lab/payments/secrets/tls"),
                certificate(31L, "k8s://lab/web/secrets/tls")), List.of(certificate(31L, "k8s://lab/web/secrets/tls")));
        when(observationRepository.findCertificateIdsWithStatus(any(), any()))
                .thenReturn(Set.of(), Set.of(31L), Set.of());

        service.reconcile(scan, OffsetDateTime.parse("2026-10-30T08:00:00Z"),
                List.of(failed("K8S_NAMESPACE", "payments")));

        assertThat(forbidden.getStatus()).isEqualTo(DiscoveryObservationStatus.PRESENT);
        assertThat(readable.getStatus()).isEqualTo(DiscoveryObservationStatus.MISSING);
    }

    private static com.certmanagement.messaging.model.DiscoveryFailedScope failed(String type, String id) {
        return com.certmanagement.messaging.model.DiscoveryFailedScope.builder()
                .scopeType(type).scopeId(id).errorCode("ACCESS_DENIED").message("denied").build();
    }

    private DiscoveredCertEntity certificate(Long id, String resourceId) {
        return DiscoveredCertEntity.builder()
                .id(id)
                .resourceId(resourceId)
                .inventoryStatus(DiscoveryInventoryStatus.PRESENT)
                .build();
    }

    private DiscoveredCertObservationEntity observation(Long certificateId, String scope, String requestId) {
        return DiscoveredCertObservationEntity.builder()
                .discoveredCertId(certificateId)
                .scopeKey(scope)
                .status(DiscoveryObservationStatus.PRESENT)
                .lastSeenRequestId(requestId)
                .build();
    }

    private DiscoveredCertEntity certificate(Long id) {
        return DiscoveredCertEntity.builder()
                .id(id)
                .inventoryStatus(DiscoveryInventoryStatus.PRESENT)
                .build();
    }
}
