// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.OrgTypeResolver;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.certmanagement.service.cbom.CertificateInventoryChangedEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.Optional;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Supplementary coverage for {@link CertPersistenceService}: the various {@code markXxxPublishFailed}
 * paths, bulk org-wide soft delete, and the after-commit KV-delete publish hooks (driven by manually
 * managing a {@link TransactionSynchronizationManager} synchronization scope).
 */
@ExtendWith(MockitoExtension.class)
class CertPersistenceServiceMoreTest {

    @Mock private CertificateRepository         certificateRepository;
    @Mock private CertificateEventRepository    eventRepository;
    @Mock private RenewalScheduleRepository     renewalScheduleRepository;
    @Mock private DeploymentRepository          deploymentRepository;
    @Mock private DomainCredentialConfigRepository domainCredConfigRepository;
    @Mock private CertManualIssuanceStateRepository certManualIssuanceStateRepository;
    @Mock private OrgTypeResolver orgTypeResolver;
    @Mock private CertAgentPublisher certAgentPublisher;
    @Mock private ApplicationEventPublisher eventPublisher;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private static final Long ORG_ID = 1L;
    private static final String XREF = "cert-abc123";

    @AfterEach
    void tearDown() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private CertPersistenceService newService(boolean withPublisher) {
        lenient().when(orgTypeResolver.resolve(any(Long.class))).thenReturn("B2B");
        CertPersistenceService service = new CertPersistenceService(
                certificateRepository, eventRepository, renewalScheduleRepository, deploymentRepository,
                domainCredConfigRepository, certManualIssuanceStateRepository,
                objectMapper, orgTypeResolver, eventPublisher, org.mockito.Mockito.mock(CertificateFeatureLocks.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
        if (withPublisher) {
            ReflectionTestUtils.setField(service, "certAgentPublisher", certAgentPublisher);
        }
        return service;
    }

    private static CertificateRepository.CertificateKvPath kvPath(String xref, String handle) {
        return new CertificateRepository.CertificateKvPath() {
            @Override public String getCertificateXref() { return xref; }
            @Override public String getCertSecretHandle() { return handle; }
        };
    }

    private CertificateEntity cert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(5L).organizationId(ORG_ID).domain("example.com").build();
        return CertificateEntity.builder()
                .certificateXref(XREF).userDomainCertId(5L).userDomainCert(udc).status(status).build();
    }

    private void fireAfterCommit() {
        for (TransactionSynchronization sync : TransactionSynchronizationManager.getSynchronizations()) {
            sync.afterCommit();
        }
    }

    // ----------------------------------------------------------------- //
    //  markIssuancePublishFailed
    // ----------------------------------------------------------------- //

    @Test
    void markIssuancePublishFailed_setsFailedAndInsertsEvent() {
        CertPersistenceService service = newService(false);
        CertificateEntity c = cert("PENDING");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));

        service.markIssuancePublishFailed(XREF, ORG_ID, "req", "corr", "boom");

        assertThat(c.getStatus()).isEqualTo("FAILED");
        assertThat(c.getLastErrorMessage()).isEqualTo("boom");
        verify(certificateRepository).save(c);
        verify(eventRepository).save(any());
    }

    @Test
    void markIssuancePublishFailed_certMissing_stillInsertsEvent() {
        CertPersistenceService service = newService(false);
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.empty());

        service.markIssuancePublishFailed(XREF, ORG_ID, "req", "corr", null);

        verify(certificateRepository, never()).save(any());
        verify(eventRepository).save(any());
    }

    // ----------------------------------------------------------------- //
    //  markRenewalPublishFailed
    // ----------------------------------------------------------------- //

    @Test
    void markRenewalPublishFailed_revertsPreviousAndFailsRenewedAndDisablesSchedule() {
        CertPersistenceService service = newService(false);
        CertificateEntity prev = cert("RENEWING");
        CertificateEntity renewed = cert("PENDING");
        renewed.setCertificateXref("cert-renewed");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(prev));
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-renewed", ORG_ID))
                .thenReturn(Optional.of(renewed));
        com.certmanagement.entity.RenewalScheduleEntity rs =
                com.certmanagement.entity.RenewalScheduleEntity.builder().certificateXref(XREF).build();
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(rs));

        service.markRenewalPublishFailed(XREF, "cert-renewed", ORG_ID, "ACTIVE", "req", "corr", "boom");

        assertThat(prev.getStatus()).isEqualTo("ACTIVE");
        assertThat(renewed.getStatus()).isEqualTo("RENEWAL_FAILED");
        assertThat(rs.getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(rs.getNextAttemptAt()).isAfter(OffsetDateTime.now());
        verify(renewalScheduleRepository).save(rs);
        verify(eventRepository).save(any());
    }

    @Test
    void markRenewalPublishFailed_blankRenewedXref_skipsRenewedLookup() {
        CertPersistenceService service = newService(false);
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.empty());
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());

        service.markRenewalPublishFailed(XREF, "  ", ORG_ID, "ACTIVE", "req", "corr", "boom");

        verify(certificateRepository, times(1)).findByCertificateXrefAndOrganizationId(anyString(), eq(ORG_ID));
        verify(eventRepository).save(any());
    }

    @Test
    void aManualRenewalOfAHeldSchedule_keepsTheHoldWhenItStartsAndWhenItsPublishFails() {
        CertPersistenceService service = newService(false);
        CertificateEntity prev = cert("ACTIVE");
        CertificateEntity renewed = cert("PENDING");
        renewed.setCertificateXref("cert-renewed");
        RenewalScheduleEntity held = RenewalScheduleEntity.builder()
                .certificateXref(XREF).enabled(false).lastRenewalStatus("FEATURE_HOLD").build();
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(held));
        when(certificateRepository.save(any())).thenAnswer(call -> call.getArgument(0));
        when(certificateRepository.tryMarkRenewing(eq(XREF), any(), any())).thenReturn(1);

        service.persistRenewal(prev, renewed, null, null, "ACTIVE", "req", "corr");
        assertThat(held.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");

        service.markRenewalPublishFailed(XREF, null, ORG_ID, "ACTIVE", "req", "corr", "boom");
        assertThat(held.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        assertThat(held.getEnabled()).isFalse();
    }

    @Test
    void aManualRenewalOfACertificateAlreadyRenewing_isRefusedAndWritesNothing() {
        CertPersistenceService service = newService(false);
        when(certificateRepository.tryMarkRenewing(eq(XREF), any(), any())).thenReturn(0);

        DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                .deploymentTargets(List.of("cred-old")).build();

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.persistRenewal(cert("ACTIVE"),
                        cert("PENDING"), config, List.of("cred-new"), "ACTIVE", "req", "corr"))
                .isInstanceOf(com.certmanagement.exception.DuplicateResourceException.class)
                .hasMessageContaining("already has a renewal in progress");
        assertThat(config.getDeploymentTargets()).containsExactly("cred-old");
        verify(domainCredConfigRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
        verify(eventRepository, never()).save(any());
    }

    // ----------------------------------------------------------------- //
    //  markDeploymentPublishFailed
    // ----------------------------------------------------------------- //

    @Test
    void markDeploymentPublishFailed_revertsStatusAndInsertsEvent() {
        CertPersistenceService service = newService(false);
        CertificateEntity c = cert("DEPLOYING");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));

        service.markDeploymentPublishFailed(XREF, ORG_ID, "ACTIVE", "req", "corr", "boom");

        assertThat(c.getStatus()).isEqualTo("ACTIVE");
        verify(certificateRepository).save(c);
        verify(eventRepository).save(any());
    }

    // ----------------------------------------------------------------- //
    //  markRevocationPublishFailed
    // ----------------------------------------------------------------- //

    @Test
    void markRevocationPublishFailed_whenRevoking_marksFailed() {
        CertPersistenceService service = newService(false);
        CertificateEntity c = cert("REVOKING");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));

        service.markRevocationPublishFailed(XREF, ORG_ID, "req", "corr", "boom");

        assertThat(c.getStatus()).isEqualTo("REVOCATION_FAILED");
        verify(certificateRepository).save(c);
        verify(eventRepository).save(any());
    }

    @Test
    void markRevocationPublishFailed_whenNotRevoking_skips() {
        CertPersistenceService service = newService(false);
        CertificateEntity c = cert("ACTIVE");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));

        service.markRevocationPublishFailed(XREF, ORG_ID, "req", "corr", "boom");

        assertThat(c.getStatus()).isEqualTo("ACTIVE");
        verify(certificateRepository, never()).save(any());
        verify(eventRepository, never()).save(any());
    }

    // ----------------------------------------------------------------- //
    //  softDeleteAndInsertEvent — afterCommit KV publish
    // ----------------------------------------------------------------- //

    @Test
    void softDelete_withKvPathAndPublisher_publishesKvDeleteAfterCommit() {
        CertPersistenceService service = newService(true);
        CertificateEntity c = cert("ACTIVE");
        c.setCertSecretHandle("kv-path");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));
        when(certificateRepository.softDelete(XREF, ORG_ID)).thenReturn(1);

        TransactionSynchronizationManager.initSynchronization();
        try {
            int updated = service.softDeleteAndInsertEvent(XREF, ORG_ID, "ACTIVE", "req", "corr");
            assertThat(updated).isEqualTo(1);
            fireAfterCommit();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }

        verify(certAgentPublisher).publishKvDeleteCommand(eq(XREF), eq("kv-path"), eq("1"), eq("B2B"));
        verify(eventPublisher).publishEvent(any(CertificateInventoryChangedEvent.class));
    }

    @Test
    void softDelete_afterCommitPublishThrows_swallowed() {
        CertPersistenceService service = newService(true);
        CertificateEntity c = cert("ACTIVE");
        c.setCertSecretHandle("kv-path");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));
        when(certificateRepository.softDelete(XREF, ORG_ID)).thenReturn(1);
        doThrow(new RuntimeException("publish boom")).when(certAgentPublisher)
                .publishKvDeleteCommand(any(), any(), any(), any());

        TransactionSynchronizationManager.initSynchronization();
        try {
            service.softDeleteAndInsertEvent(XREF, ORG_ID, "ACTIVE", "req", "corr");
            fireAfterCommit();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }

        verify(certAgentPublisher).publishKvDeleteCommand(any(), any(), any(), any());
    }

    @Test
    void softDelete_noKvPath_doesNotRegisterSynchronization() {
        CertPersistenceService service = newService(true);
        CertificateEntity c = cert("ACTIVE"); // certSecretHandle null
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID))
                .thenReturn(Optional.of(c));
        when(certificateRepository.softDelete(XREF, ORG_ID)).thenReturn(1);

        TransactionSynchronizationManager.initSynchronization();
        try {
            service.softDeleteAndInsertEvent(XREF, ORG_ID, "ACTIVE", "req", "corr");
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }

        verifyNoInteractions(certAgentPublisher);
    }

    // ----------------------------------------------------------------- //
    //  softDeleteAllByOrganizationId
    // ----------------------------------------------------------------- //

    @Test
    void softDeleteAllByOrganizationId_publishesKvDeletesForEachActiveCert() {
        CertPersistenceService service = newService(true);
        when(certificateRepository.findActiveWithKvPathByOrganizationId(ORG_ID))
                .thenReturn(List.of(kvPath(XREF, "kv-1"), kvPath("cert-2", "kv-2"),
                        kvPath("cert-3", null))); // no kv path -> skipped

        TransactionSynchronizationManager.initSynchronization();
        try {
            service.softDeleteAllByOrganizationId(ORG_ID);
            fireAfterCommit();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }
        verify(eventPublisher).publishEvent(any(CertificateInventoryChangedEvent.class));

        verify(certificateRepository).softDeleteAllByOrganizationId(ORG_ID);
        verify(renewalScheduleRepository).softDeleteByOrganizationId(ORG_ID);
        verify(certAgentPublisher).publishKvDeleteCommand(eq(XREF), eq("kv-1"), eq("1"), eq("B2B"));
        verify(certAgentPublisher).publishKvDeleteCommand(eq("cert-2"), eq("kv-2"), eq("1"), eq("B2B"));
        verify(certAgentPublisher, never()).publishKvDeleteCommand(eq("cert-3"), any(), any(), any());
    }

    @Test
    void softDeleteAllByOrganizationId_publishLookupFails_swallowedAndStillDeletes() {
        CertPersistenceService service = newService(true);
        when(certificateRepository.findActiveWithKvPathByOrganizationId(ORG_ID))
                .thenThrow(new RuntimeException("lookup boom"));

        service.softDeleteAllByOrganizationId(ORG_ID);

        verify(certificateRepository).softDeleteAllByOrganizationId(ORG_ID);
    }

    @Test
    void softDeleteAllByOrganizationId_noPublisher_skipsKvCollection() {
        CertPersistenceService service = newService(false);

        service.softDeleteAllByOrganizationId(ORG_ID);

        verify(certificateRepository, never()).findActiveWithKvPathByOrganizationId(any());
        verify(certificateRepository).softDeleteAllByOrganizationId(ORG_ID);
    }

    @Test
    void softDeleteAllByOrganizationId_afterCommitPublishThrows_swallowed() {
        CertPersistenceService service = newService(true);
        when(certificateRepository.findActiveWithKvPathByOrganizationId(ORG_ID))
                .thenReturn(List.of(kvPath(XREF, "kv-1")));
        doThrow(new RuntimeException("boom")).when(certAgentPublisher)
                .publishKvDeleteCommand(any(), any(), any(), any());

        TransactionSynchronizationManager.initSynchronization();
        try {
            service.softDeleteAllByOrganizationId(ORG_ID);
            fireAfterCommit();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }

        verify(certAgentPublisher).publishKvDeleteCommand(any(), any(), any(), any());
    }
}
