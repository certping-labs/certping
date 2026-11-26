// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.EventSource;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.security.GatewayRequestContext;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertPersistenceServiceTest {

    @Mock private CertificateRepository         certificateRepository;
    @Mock private CertificateEventRepository    eventRepository;
    @Mock private RenewalScheduleRepository     renewalScheduleRepository;
        @Mock private DeploymentRepository          deploymentRepository;
    @Mock private DomainCredentialConfigRepository domainCredConfigRepository;
    @Mock private CertManualIssuanceStateRepository certManualIssuanceStateRepository;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;
    @Mock private ApplicationEventPublisher eventPublisher;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private long idCounter = 100;

    private static final Long ORGANIZATION_ID = 1L;
    private static final String XREF = "cert-abc123";

        private CertPersistenceService newService() {
                org.mockito.Mockito.lenient().when(orgTypeResolver.resolve(org.mockito.ArgumentMatchers.any(Long.class))).thenReturn("B2B");
                return new CertPersistenceService(
                                certificateRepository,
                                eventRepository,
                                renewalScheduleRepository,
                                deploymentRepository,
                                domainCredConfigRepository,
                                certManualIssuanceStateRepository,
                                objectMapper,
                                orgTypeResolver,
                                eventPublisher, org.mockito.Mockito.mock(CertificateFeatureLocks.class), org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
        }

    private CertificateEntity buildCert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();
        return CertificateEntity.builder()
                .certificateXref(XREF)
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .status(status)
                .build();
    }

        @Test
        void softDeleteAndInsertEvent_whenUpdated_disablesScheduleAndSavesDeletedEvent() {
                CertPersistenceService service = newService();

                when(certificateRepository.softDelete(XREF, ORGANIZATION_ID)).thenReturn(1);

                GatewayRequestContext.set(101, ORGANIZATION_ID.toString(), "req-del-1", "user@example.com");
                try {
                        int updated = service.softDeleteAndInsertEvent(
                                        XREF, ORGANIZATION_ID, "ACTIVE", "req-del-1", "corr-del-1");
                        assertThat(updated).isEqualTo(1);
                } finally {
                        GatewayRequestContext.clear();
                }

                verify(renewalScheduleRepository).softDeleteByXref(XREF);
                verify(deploymentRepository).softDeleteByCertificateXrefAndOrganizationId(XREF, ORGANIZATION_ID);

                ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
                verify(eventRepository).save(eventCaptor.capture());
                CertificateEventEntity event = eventCaptor.getValue();

                assertThat(event.getEventType()).isEqualTo("CERT_DELETED");
                assertThat(event.getFromStatus()).isEqualTo("ACTIVE");
                assertThat(event.getToStatus()).isEqualTo("DELETED");
                assertThat(event.getSource()).isEqualTo(EventSource.CERT_MANAGER.value());
                assertThat(event.getRequestId()).isEqualTo("req-del-1");
                assertThat(event.getCorrelationId()).isEqualTo("corr-del-1");
                assertThat(event.getUserId()).isEqualTo(101);
        }

        @Test
        void softDeleteAndInsertEvent_whenNoRowsUpdated_skipsScheduleAndEvent() {
                CertPersistenceService service = newService();

                when(certificateRepository.softDelete(XREF, ORGANIZATION_ID)).thenReturn(0);

                int updated = service.softDeleteAndInsertEvent(
                                XREF, ORGANIZATION_ID, "ACTIVE", "req-del-2", "corr-del-2");

                assertThat(updated).isEqualTo(0);
                verify(renewalScheduleRepository, never()).softDeleteByXref(any());
                verify(deploymentRepository, never()).softDeleteByCertificateXrefAndOrganizationId(any(), any());
                verify(eventRepository, never()).save(any());
        }

    @Test
    void persistRevocation_savesEventWithUserIdAndDefaultReason() {
                CertPersistenceService service = newService();

        RevokeRequest request = new RevokeRequest();
        CertificateEntity revoking = buildCert("REVOKING");

        when(certificateRepository.tryMarkRevoking(eq(XREF), eq(ORGANIZATION_ID), any()))
                .thenReturn(1);
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(revoking));
        when(renewalScheduleRepository.findByCertificateXref(XREF))
                .thenReturn(Optional.empty());

        GatewayRequestContext.set(77, ORGANIZATION_ID.toString(), "req-1", "user@example.com");
        try {
            Optional<CertificateEntity> result = service.persistRevocation(
                    XREF, ORGANIZATION_ID, "ACTIVE", request, "req-1", "corr-1");
            assertThat(result).isPresent();
        } finally {
            GatewayRequestContext.clear();
        }

        verify(certificateRepository).tryMarkRevoking(eq(XREF), eq(ORGANIZATION_ID), any());

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());

        CertificateEventEntity event = eventCaptor.getValue();
        assertThat(event.getEventType()).isEqualTo("REVOCATION_REQUESTED");
        assertThat(event.getFromStatus()).isEqualTo("ACTIVE");
        assertThat(event.getToStatus()).isEqualTo("REVOKING");
        assertThat(event.getUserId()).isEqualTo(77);
        assertThat(event.getReason()).isEqualTo("UNSPECIFIED");
    }

    @Test
    void persistRevocation_usesProvidedReasonInEvent() {
                CertPersistenceService service = newService();

        RevokeRequest request = new RevokeRequest();
        request.setReason("KEY_COMPROMISE");
        CertificateEntity revoking = buildCert("REVOKING");

        when(certificateRepository.tryMarkRevoking(eq(XREF), eq(ORGANIZATION_ID), any()))
                .thenReturn(1);
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(revoking));
        when(renewalScheduleRepository.findByCertificateXref(XREF))
                .thenReturn(Optional.empty());

        GatewayRequestContext.set(99, ORGANIZATION_ID.toString(), "req-2", "user@example.com");
        try {
            Optional<CertificateEntity> result = service.persistRevocation(
                    XREF, ORGANIZATION_ID, "ACTIVE", request, "req-2", "corr-2");
            assertThat(result).isPresent();
        } finally {
            GatewayRequestContext.clear();
        }

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());

        CertificateEventEntity event = eventCaptor.getValue();
        assertThat(event.getUserId()).isEqualTo(99);
        assertThat(event.getReason()).isEqualTo("KEY_COMPROMISE");
    }

    @Test
    void persistRevocation_whenScheduleExists_disablesSchedule() {
                CertPersistenceService service = newService();

        RevokeRequest request = new RevokeRequest();
        CertificateEntity revoking = buildCert("REVOKING");
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(XREF)
                .enabled(true)
                .build();

        when(certificateRepository.tryMarkRevoking(eq(XREF), eq(ORGANIZATION_ID), any()))
                .thenReturn(1);
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(revoking));
        when(renewalScheduleRepository.findByCertificateXref(XREF))
                .thenReturn(Optional.of(schedule));

        Optional<CertificateEntity> result = service.persistRevocation(
                XREF, ORGANIZATION_ID, "ACTIVE", request, "req-4", "corr-4");

        assertThat(result).isPresent();
        assertThat(schedule.getEnabled()).isFalse();
        verify(renewalScheduleRepository).save(schedule);
    }

    @Test
    void persistRevocation_whenTryMarkRevokingReturnsZero_returnsEmptyWithoutEvent() {
                CertPersistenceService service = newService();

        RevokeRequest request = new RevokeRequest();
        when(certificateRepository.tryMarkRevoking(eq(XREF), eq(ORGANIZATION_ID), any()))
                .thenReturn(0);

        Optional<CertificateEntity> result = service.persistRevocation(
                XREF, ORGANIZATION_ID, "ACTIVE", request, "req-3", "corr-3");

        assertThat(result).isEmpty();
        verify(eventRepository, never()).save(any());
    }

    // ================================================================== //
    //  userId propagation via GatewayRequestContext (9-arg insertEvent)
    // ================================================================== //

    @Test
    void persistIssuance_withUserContext_savesEventWithUserId() {
                CertPersistenceService service = newService();

        Long configId = ++idCounter;
        DomainCredentialConfigEntity savedConfig = DomainCredentialConfigEntity.builder()
                .id(configId)
                .userDomainCertId(++idCounter)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.save(any())).thenReturn(savedConfig);

        CertificateEntity cert = buildCert("PENDING");
        cert.setCaProvider(CaProvider.LETS_ENCRYPT); // Map.of rejects null values
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(++idCounter)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of())
                .build();
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(XREF)
                .validTo(OffsetDateTime.now().plusYears(1))
                .renewalEligibleAt(OffsetDateTime.now().plusDays(335))
                .build();

        GatewayRequestContext.set(42, ORGANIZATION_ID.toString(), "req-10", "user@example.com");
        try {
            service.persistIssuance(cert, credConfig, schedule, "req-10", "corr-10");
        } finally {
            GatewayRequestContext.clear();
        }

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo("ISSUANCE_REQUESTED");
        assertThat(captor.getValue().getUserId()).isEqualTo(42);
    }

    @Test
    void persistIssuance_withoutUserContext_savesEventWithNullUserId() {
                CertPersistenceService service = newService();

        Long configId = ++idCounter;
        DomainCredentialConfigEntity savedConfig = DomainCredentialConfigEntity.builder()
                .id(configId)
                .userDomainCertId(++idCounter)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.save(any())).thenReturn(savedConfig);

        CertificateEntity cert = buildCert("PENDING");
        cert.setCaProvider(CaProvider.LETS_ENCRYPT); // Map.of rejects null values
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(++idCounter)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of())
                .build();
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(XREF)
                .validTo(OffsetDateTime.now().plusYears(1))
                .renewalEligibleAt(OffsetDateTime.now().plusDays(335))
                .build();

        GatewayRequestContext.clear();
        service.persistIssuance(cert, credConfig, schedule, "req-11", "corr-11");

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo("ISSUANCE_REQUESTED");
        assertThat(captor.getValue().getUserId()).isNull();
    }

    @Test
    void persistRenewal_withUserContext_savesEventWithUserId() {
                CertPersistenceService service = newService();

        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(certificateRepository.save(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(certificateRepository.tryMarkRenewing(any(), any(), any())).thenReturn(1);

                CertificateEntity cert = buildCert("ACTIVE");
                CertificateEntity renewedDraft = buildCert("PENDING");
                renewedDraft.setCertificateXref("cert-renewed-1");

        GatewayRequestContext.set(55, ORGANIZATION_ID.toString(), "req-20", "user@example.com");
        try {
                        service.persistRenewal(cert, renewedDraft, null, null, "ACTIVE", "req-20", "corr-20");
        } finally {
            GatewayRequestContext.clear();
        }

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo("RENEWAL_REQUESTED");
        assertThat(captor.getValue().getUserId()).isEqualTo(55);
    }

    @Test
    void persistDeployment_withUserContext_savesEventWithUserId() {
                CertPersistenceService service = newService();

        CertificateEntity cert = buildCert("ACTIVE");
        cert.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");

        GatewayRequestContext.set(99, ORGANIZATION_ID.toString(), "req-30", "user@example.com");
        try {
            service.persistDeployment(cert, "ACTIVE", "req-30", "corr-30", "AZURE_KV", "");
        } finally {
            GatewayRequestContext.clear();
        }

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo("DEPLOYMENT_REQUESTED");
        assertThat(captor.getValue().getUserId()).isEqualTo(99);
    }

    @Test
    void persistIssuance_existingConfig_upsertsAndReusesConfigId() {
                CertPersistenceService service = newService();

        CertificateEntity cert = buildCert("PENDING");
        cert.setCaProvider(CaProvider.LETS_ENCRYPT);

        Long existingConfigId = ++idCounter;
        DomainCredentialConfigEntity existing = DomainCredentialConfigEntity.builder()
                .id(existingConfigId)
                .userDomainCertId(cert.getUserDomainCertId())
                .dnsConfig(Map.of("example.com", "old-dns"))
                .deploymentTargets(List.of("old-deploy"))
                .build();

        DomainCredentialConfigEntity newConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(cert.getUserDomainCertId())
                .dnsConfig(Map.of("example.com", "new-dns"))
                .deploymentTargets(List.of("new-deploy"))
                .build();

        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(XREF)
                .validTo(OffsetDateTime.now().plusYears(1))
                .renewalEligibleAt(OffsetDateTime.now().plusDays(335))
                .build();

        when(domainCredConfigRepository.findByUserDomainCertId(cert.getUserDomainCertId()))
                .thenReturn(Optional.of(existing));
        when(domainCredConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.persistIssuance(cert, newConfig, schedule, "req-upsert", "corr-upsert");

        verify(domainCredConfigRepository).findByUserDomainCertId(cert.getUserDomainCertId());
        ArgumentCaptor<DomainCredentialConfigEntity> configCaptor =
                ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(domainCredConfigRepository).save(configCaptor.capture());
        assertThat(configCaptor.getValue().getId()).isEqualTo(existingConfigId);
        assertThat(configCaptor.getValue().getDnsConfig()).containsEntry("example.com", "new-dns");
        assertThat(configCaptor.getValue().getDeploymentTargets()).containsExactly("new-deploy");

        ArgumentCaptor<RenewalScheduleEntity> scheduleCaptor =
                ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(scheduleCaptor.capture());
        assertThat(scheduleCaptor.getValue().getDomainCredentialConfigId()).isEqualTo(existingConfigId);
    }
}
