// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.NotificationPublisher;
import com.certmanagement.messaging.model.CertOwnSecretDeleteCommand;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertExpiryMarkServiceTest {

    private static final Long   ORG_ID = 9L;
    private static final String XREF   = "cert-mark-xyz";

    @Mock private CertificateRepository      certificateRepository;
    @Mock private CertificateEventRepository certEventRepository;
    @Mock private RenewalScheduleRepository  renewalScheduleRepository;
    @Mock private NotificationPublisher      notificationPublisher;
    @Mock private ObjectProvider<CertAgentPublisher> certAgentPublisher;
    @Mock private CertAgentPublisher publisher;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;

    private CertExpiryMarkService service;
    private CertificateEntity cert;

    @BeforeEach
    void setUp() {
        service = new CertExpiryMarkService(
                certificateRepository, certEventRepository, renewalScheduleRepository,
                notificationPublisher, certAgentPublisher, orgTypeResolver, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
        org.mockito.Mockito.lenient().when(orgTypeResolver.resolve(org.mockito.ArgumentMatchers.any(Long.class)))
                .thenReturn("B2B");

        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(1L).organizationId(ORG_ID).domain("example.com").build();
        cert = CertificateEntity.builder()
                .certificateXref(XREF)
                .userDomainCert(udc)
                .status("ACTIVE")
                .validTo(OffsetDateTime.now().minusDays(1))
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .build();
    }

    @Test
    void tryProcessOneEligible_emptyQueue_returnsFalse() {
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.empty());

        assertThat(service.tryProcessOneEligible()).isFalse();
        verify(certificateRepository, never()).updateStatus(any(), any());
    }

    @Test
    void tryProcessOneEligible_success_updatesStatusInsertsEventDisablesScheduleAndNotifies() {
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.of(cert));
        // No transaction synchronization active -> post-commit task runs inline
        stubInlinePublisher();

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        verify(certificateRepository).updateStatus(XREF, "EXPIRED");
        verify(renewalScheduleRepository).disableSchedule(XREF);

        ArgumentCaptor<CertificateEventEntity> eventCap = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(certEventRepository).save(eventCap.capture());
        CertificateEventEntity event = eventCap.getValue();
        assertThat(event.getEventType()).isEqualTo("CERT_EXPIRED");
        assertThat(event.getFromStatus()).isEqualTo("ACTIVE");
        assertThat(event.getToStatus()).isEqualTo("EXPIRED");
        assertThat(event.getCertificateXref()).isEqualTo(XREF);
        assertThat(event.getOrganizationId()).isEqualTo(ORG_ID);

        verify(notificationPublisher).publish(eq("CERT_EXPIRED"), eq(ORG_ID.toString()), eq(XREF), any());

        ArgumentCaptor<CertOwnSecretDeleteCommand> cmdCap = ArgumentCaptor.forClass(CertOwnSecretDeleteCommand.class);
        verify(publisher).publishKvSecretDeleteCommand(cmdCap.capture());
        assertThat(cmdCap.getValue().getCertificateXref()).isEqualTo(XREF);
        assertThat(cmdCap.getValue().getReason()).isEqualTo("CERT_EXPIRED");
        assertThat(cmdCap.getValue().getCertSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/cert");
    }

    @Test
    void tryProcessOneEligible_notificationFailure_doesNotRollBack() {
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.of(cert));
        doThrow(new RuntimeException("queue down"))
                .when(notificationPublisher).publish(anyString(), anyString(), anyString(), any());
        stubInlinePublisher();

        // Should NOT throw — notification failure is swallowed
        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        verify(certificateRepository).updateStatus(XREF, "EXPIRED");
        verify(renewalScheduleRepository).disableSchedule(XREF);
    }

    @Test
    void tryProcessOneEligible_statusUpdateFailure_rethrowsForRollback() {
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.of(cert));
        doThrow(new RuntimeException("db dead"))
                .when(certificateRepository).updateStatus(any(), any());

        assertThatThrownBy(() -> service.tryProcessOneEligible())
                .isInstanceOf(RuntimeException.class)
                .hasMessage("db dead");
    }

    @Test
    void tryProcessOneEligible_blankCertSecretHandle_skipsAgentPublish() {
        cert.setCertSecretHandle("");
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.of(cert));

        service.tryProcessOneEligible();

        verify(certAgentPublisher, never()).ifAvailable(any());
    }

    @Test
    void tryProcessOneEligible_nullCertSecretHandle_skipsAgentPublish() {
        cert.setCertSecretHandle(null);
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.of(cert));

        service.tryProcessOneEligible();

        verify(certAgentPublisher, never()).ifAvailable(any());
    }

    @Test
    void tryProcessOneEligible_kvPublishFailure_isSwallowed() {
        when(certificateRepository.claimOneExpiredCert(any())).thenReturn(Optional.of(cert));
        doAnswer(inv -> {
            Consumer<CertAgentPublisher> c = inv.getArgument(0);
            c.accept(publisher);
            return null;
        }).when(certAgentPublisher).ifAvailable(any());
        doThrow(new RuntimeException("kv unreachable"))
                .when(publisher).publishKvSecretDeleteCommand(any());

        // Should NOT throw — agent publish failure is swallowed in post-commit task
        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        verify(certificateRepository).updateStatus(XREF, "EXPIRED");
    }

    @SuppressWarnings("unchecked")
    private void stubInlinePublisher() {
        doAnswer(inv -> {
            Consumer<CertAgentPublisher> c = inv.getArgument(0);
            c.accept(publisher);
            return null;
        }).when(certAgentPublisher).ifAvailable(any());
    }
}
