// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.entity.CertManualIssuanceStateEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertManualIssuanceServiceTest {

    @Mock private CertificateRepository certificateRepository;
    @Mock private CertManualIssuanceStateRepository stateRepository;
    @Mock private UserDomainCertRepository udcRepository;
    @Mock private DomainCredentialConfigRepository domainCredConfigRepository;
    @Mock private CertificateEventRepository eventRepository;
    @Mock private CertAgentPublisher publisher;
    @Mock private ObjectMapper objectMapper;
    @Mock private CertificateStatusValidator certificateStatusValidator;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;

    private CertManualIssuanceService service;
    private long idCounter = 100;

    private static final Long ORGANIZATION_ID = 1L;
    private static final Long UDC_ID = 2L;

    @BeforeEach
    void setUp() {
        service = new CertManualIssuanceService(
                certificateRepository,
                stateRepository,
                udcRepository,
                domainCredConfigRepository,
                eventRepository,
                publisher,
                objectMapper,
                certificateStatusValidator,
                orgTypeResolver,
                org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
        org.mockito.Mockito.lenient().when(orgTypeResolver.resolve(any(Long.class))).thenReturn("B2B");
    }

    @Test
    void initiateManualIssuance_noExistingConfig_createsEmptyConfig() {
        UserDomainCertEntity udc = buildUdc();
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "example.com"))
                .thenReturn(Optional.of(udc));
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(certificateRepository.save(any(CertificateEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.initiateManualIssuance(ORGANIZATION_ID, manualRequest());


        ArgumentCaptor<DomainCredentialConfigEntity> configCaptor =
                ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(domainCredConfigRepository).save(configCaptor.capture());

        DomainCredentialConfigEntity saved = configCaptor.getValue();
        assertThat(saved.getUserDomainCertId()).isEqualTo(UDC_ID);
        assertThat(saved.getDnsConfig()).isEmpty();
        assertThat(saved.getDeploymentTargets()).isEmpty();
                verify(publisher).publishManualTxtRequest(any(CertificateEntity.class), anyString(), any(), anyString(), nullable(String.class));

                ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
                verify(eventRepository).save(eventCaptor.capture());
                assertThat(eventCaptor.getValue().getEventType()).isEqualTo("MANUAL_TXT_REQUESTED");
    }

    @Test
    void initiateManualIssuance_existingConfig_clearsDnsAndDeploymentTargets() {
        UserDomainCertEntity udc = buildUdc();
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "example.com"))
                .thenReturn(Optional.of(udc));

        DomainCredentialConfigEntity existing = DomainCredentialConfigEntity.builder()
                .id(++idCounter)
                .userDomainCertId(UDC_ID)
                .dnsConfig(new LinkedHashMap<>(java.util.Map.of("example.com", "cred-dns-old")))
                .deploymentTargets(new java.util.ArrayList<>(List.of("cred-deploy-old")))
                .build();

        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(existing));
        when(domainCredConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(certificateRepository.save(any(CertificateEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.initiateManualIssuance(ORGANIZATION_ID, manualRequest());

        assertThat(existing.getDnsConfig()).isEmpty();
        assertThat(existing.getDeploymentTargets()).isEmpty();
        verify(domainCredConfigRepository).save(existing);
                verify(publisher).publishManualTxtRequest(any(CertificateEntity.class), anyString(), any(), anyString(), nullable(String.class));

                ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
                verify(eventRepository).save(eventCaptor.capture());
                assertThat(eventCaptor.getValue().getEventType()).isEqualTo("MANUAL_TXT_REQUESTED");
    }

    @Test
    void initiateManualIssuance_aSanEntryWithNamesUnderTwoDomains_isRefusedBeforeAnythingIsSaved() {
        IssueManualRequest req = canonicalManualRequest();
        req.getSanDomainEntries().get(1).setPatterns(List.of("example.tech", "shop.example.net"));

        assertThatThrownBy(() -> service.initiateManualIssuance(ORGANIZATION_ID, req))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class)
                .hasMessage("Each additional domain group must use names under one domain.");

        org.mockito.Mockito.verifyNoInteractions(udcRepository, domainCredConfigRepository, certificateRepository);
    }

    @Test
    void initiateManualIssuance_publishFailure_marksFailedAndThrows() {
        UserDomainCertEntity udc = buildUdc();
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "example.com"))
                .thenReturn(Optional.of(udc));
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(certificateRepository.save(any(CertificateEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        doThrow(new RuntimeException("queue unavailable"))
                .when(publisher).publishManualTxtRequest(any(CertificateEntity.class), anyString(), any(), anyString(), nullable(String.class));

        assertThatThrownBy(() -> service.initiateManualIssuance(ORGANIZATION_ID, manualRequest()))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("has been marked FAILED");

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, org.mockito.Mockito.atLeast(2)).save(certCaptor.capture());
        assertThat(certCaptor.getAllValues())
                .anySatisfy(saved -> assertThat(saved.getStatus()).isEqualTo("FAILED"));

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository, org.mockito.Mockito.times(2)).save(eventCaptor.capture());
        assertThat(eventCaptor.getAllValues())
                .extracting(CertificateEventEntity::getEventType)
                .containsExactlyInAnyOrder("MANUAL_TXT_REQUESTED", "MANUAL_TXT_PUBLISH_FAILED");
    }

    @Test
    void triggerValidation_publishFailure_marksFailedAndThrows() {
        CertificateEntity cert = CertificateEntity.builder()
                .id(++idCounter)
                .certificateXref("cert-validate-1")
                .userDomainCertId(UDC_ID)
                .userDomainCert(buildUdc())
                .status("AWAITING_DNS")
                .build();

        CertManualIssuanceStateEntity state = CertManualIssuanceStateEntity.builder()
                .certXref("cert-validate-1")
                .organizationId(ORGANIZATION_ID)
                .acmeOrderUrl("https://acme.test/order/1")
                .acmeAccountHandle("https://kv/acme")
                .txtRecords("[]")
                .expiresAt(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(30))
                .build();

        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-validate-1", ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(stateRepository.findByCertXref("cert-validate-1")).thenReturn(Optional.of(state));
        when(certificateRepository.save(any(CertificateEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(certificateStatusValidator.isAllowedForOperation(
                anyString(),
                eq(CertificateStatusValidator.CertOperation.ISSUE_MANUAL_VALIDATE_DNS)))
                .thenReturn(true);
        doThrow(new RuntimeException("queue unavailable"))
                .when(publisher).publishManualDnsValidate(any(CertificateEntity.class), anyString(), any(CertManualIssuanceStateEntity.class), anyString(), nullable(String.class));

        assertThatThrownBy(() -> service.triggerValidation("cert-validate-1", ORGANIZATION_ID))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("has been marked FAILED");

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, org.mockito.Mockito.atLeast(2)).save(certCaptor.capture());
        assertThat(certCaptor.getAllValues())
                .anySatisfy(saved -> assertThat(saved.getStatus()).isEqualTo("FAILED"));

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository, org.mockito.Mockito.times(2)).save(eventCaptor.capture());
        assertThat(eventCaptor.getAllValues())
                .extracting(CertificateEventEntity::getEventType)
                .containsExactlyInAnyOrder("MANUAL_DNS_VALIDATE_REQUESTED", "MANUAL_DNS_VALIDATE_PUBLISH_FAILED");
    }

    // ================================================================== //
    //  Canonical scenario — manual issuance consistency
    // ================================================================== //

    /**
     * Proves that the manual flow stores the SAME san_domains as automated issuance
     * for an identical domain + SAN entry set.  The certificate that ACME issues
     * will therefore contain the same SANs regardless of which flow was used.
     */
    @Test
    void initiateManualIssuance_canonicalWildcardSanRequest_storesSameSanDomainsAsAutomated() {
        UserDomainCertEntity udc = buildUdcForDomain("auto.example.pro");
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "auto.example.pro"))
                .thenReturn(Optional.of(udc));
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        when(certificateRepository.save(any(CertificateEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        service.initiateManualIssuance(ORGANIZATION_ID, canonicalManualRequest());

        ArgumentCaptor<CertificateEntity> certCaptor =
                ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());

        // Identical to what automated issuance stores — same ACME order domains
        assertThat(certCaptor.getValue().getSanDomains()).containsExactly(
                "*.auto.example.pro",
                "example.pro",
                "*.example.pro",
                "example.tech",
                "*.example.tech");
    }

    /**
     * Proves that the manual flow sends the same per-group-pruned patterns to the agent
     * as automated issuance (minus DNS credential paths, which manual flow doesn't have).
     */
    @Test
    @SuppressWarnings("unchecked")
    void initiateManualIssuance_canonicalWildcardSanRequest_publishesPrunedSanEntries() {
        UserDomainCertEntity udc = buildUdcForDomain("auto.example.pro");
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "auto.example.pro"))
                .thenReturn(Optional.of(udc));
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        when(certificateRepository.save(any(CertificateEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        service.initiateManualIssuance(ORGANIZATION_ID, canonicalManualRequest());

        ArgumentCaptor<List<IssueManualRequest.SanDomainEntry>> entriesCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(publisher).publishManualTxtRequest(any(CertificateEntity.class), anyString(), entriesCaptor.capture(), anyString(), nullable(String.class));

        List<IssueManualRequest.SanDomainEntry> entries = entriesCaptor.getValue();
        assertThat(entries).hasSize(2);

        List<List<String>> allPatterns = entries.stream()
                .map(IssueManualRequest.SanDomainEntry::getPatterns)
                .toList();

        // Same pruned patterns as automated issuance sends — redundant app.* subdomains removed
        assertThat(allPatterns).containsExactlyInAnyOrder(
                List.of("*.auto.example.pro", "example.pro", "*.example.pro"),
                List.of("example.tech", "*.example.tech"));
    }

    private UserDomainCertEntity buildUdcForDomain(String domain) {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(ORGANIZATION_ID)
                .domain(domain)
                .build();
    }

    private IssueManualRequest canonicalManualRequest() {
        IssueManualRequest req = new IssueManualRequest();
        req.setDomain("auto.example.pro");
        req.setWildcard(true);
        req.setSan(true);

        IssueManualRequest.SanDomainEntry entry1 = new IssueManualRequest.SanDomainEntry();
        entry1.setPatterns(List.of("app.auto.example.pro", "*.auto.example.pro",
                                   "app.example.pro", "example.pro", "*.example.pro"));

        IssueManualRequest.SanDomainEntry entry2 = new IssueManualRequest.SanDomainEntry();
        entry2.setPatterns(List.of("example.tech", "app.example.tech", "*.example.tech"));

        req.setSanDomainEntries(List.of(entry1, entry2));
        return req;
    }

    private UserDomainCertEntity buildUdc() {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();
    }

    private IssueManualRequest manualRequest() {
        IssueManualRequest req = new IssueManualRequest();
        req.setDomain("example.com");
        req.setWildcard(false);
        req.setSan(false);
        return req;
    }
}
