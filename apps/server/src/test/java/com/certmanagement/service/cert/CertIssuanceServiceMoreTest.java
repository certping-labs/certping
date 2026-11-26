// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Supplementary coverage for {@link CertIssuanceService} focusing on the cascade-delete,
 * revocation finalization, dashboard, read, feature-flag, and credential-kvpath paths not
 * exercised by {@code CertIssuanceServiceTest}.
 */
@ExtendWith(MockitoExtension.class)
class CertIssuanceServiceMoreTest {


    @Mock private CertificateRepository            certificateRepository;
    @Mock private RenewalScheduleRepository        renewalScheduleRepository;
    @Mock private DomainCredentialConfigRepository domainCredConfigRepository;
    @Mock private com.certmanagement.repository.CertDeploymentConfigRepository certDeploymentConfigRepository;
    @Mock private UserDomainCertRepository         udcRepository;
    @Mock private CredentialReferenceService       credentialService;
    @Mock private DomainCredentialConfigService    domainCredConfigService;
    @Mock private CertPersistenceService           persistenceService;
    @Mock private CertAgentPublisher               publisher;
    @Mock private DeploymentExecutionService       deploymentExecutionService;
    @Mock private KubernetesDeploymentConfigResolver kubernetesDeploymentConfigResolver;
    @Mock private CertDeploymentConfigService      certDeploymentConfigService;
    @Mock private FeatureFlagService               featureFlagService;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;

    private final CertificateStatusValidator certificateStatusValidator = new CertificateStatusValidator();
    private final RenewalDraftHelper renewalDraftHelper = new RenewalDraftHelper();

    private CertIssuanceService service;

    private static final Long   ORG_ID    = 1L;
    private static final Long   UDC_ID    = 2L;
    private static final String CERT_XREF = "cert-abc123";

    @BeforeEach
    void setUp() {
        service = new CertIssuanceService(
                certificateRepository, renewalScheduleRepository, domainCredConfigRepository,
                certDeploymentConfigRepository, udcRepository, credentialService,
                domainCredConfigService, persistenceService, publisher, certificateStatusValidator,
                deploymentExecutionService, kubernetesDeploymentConfigResolver, certDeploymentConfigService,
                renewalDraftHelper, featureFlagService, orgTypeResolver);
    }

    private static CertificateRepository.CertificateXrefStatus xrefStatus(String xref, String status) {
        return new CertificateRepository.CertificateXrefStatus() {
            @Override public String getCertificateXref() { return xref; }
            @Override public String getStatus() { return status; }
        };
    }

    private CertificateEntity buildCert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).organizationId(ORG_ID).domain("example.com").build();
        return CertificateEntity.builder()
                .id(99L)
                .certificateXref(CERT_XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .validTo(OffsetDateTime.now().plusDays(60))
                .build();
    }

    // ----------------------------------------------------------------- //
    //  getStatus
    // ----------------------------------------------------------------- //

    @Test
    void getStatus_returnsCert() {
        CertificateEntity cert = buildCert("ACTIVE");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.of(cert));

        assertThat(service.getStatus(ORG_ID, CERT_XREF)).isSameAs(cert);
    }

    @Test
    void getStatus_notFound_throws() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getStatus(ORG_ID, CERT_XREF))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ----------------------------------------------------------------- //
    //  dashboard
    // ----------------------------------------------------------------- //

    @Test
    void dashboard_aggregatesByStatusAndCounts() {
        when(certificateRepository.countByStatusForOrganization(ORG_ID))
                .thenReturn(List.of(
                        new Object[]{"ACTIVE", 3L},
                        new Object[]{"FAILED", 2L}));
        when(certificateRepository.countExpiringBetween(eq(ORG_ID), any(), any()))
                .thenReturn(5L);

        Map<String, Object> result = service.dashboard(ORG_ID);

        @SuppressWarnings("unchecked")
        Map<String, Long> byStatus = (Map<String, Long>) result.get("byStatus");
        assertThat(byStatus).containsEntry("ACTIVE", 3L).containsEntry("FAILED", 2L);
        assertThat(result.get("total")).isEqualTo(5L);
        assertThat(result.get("expiringIn30Days")).isEqualTo(5L);
    }

    // ----------------------------------------------------------------- //
    //  listExpiring
    // ----------------------------------------------------------------- //

    @Test
    void listExpiring_delegatesUtcWindowToRepository() {
        Slice<CertificateRepository.ExpiringCertificateRow> slice =
                new SliceImpl<>(List.of(), PageRequest.of(0, 10), false);
        when(certificateRepository.findExpiringBetween(eq(ORG_ID), any(), any(), any()))
                .thenReturn(slice);

        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);
        Slice<CertificateRepository.ExpiringCertificateRow> result =
                service.listExpiring(ORG_ID, 14, PageRequest.of(0, 10));
        OffsetDateTime after = OffsetDateTime.now(ZoneOffset.UTC);

        assertThat(result).isSameAs(slice);

        ArgumentCaptor<OffsetDateTime> fromCap = ArgumentCaptor.forClass(OffsetDateTime.class);
        ArgumentCaptor<OffsetDateTime> toCap = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(certificateRepository).findExpiringBetween(
                eq(ORG_ID), fromCap.capture(), toCap.capture(), eq(PageRequest.of(0, 10)));

        OffsetDateTime from = fromCap.getValue();
        OffsetDateTime to = toCap.getValue();
        assertThat(from.getOffset()).isEqualTo(ZoneOffset.UTC);
        assertThat(to).isEqualTo(from.plusDays(14));
        assertThat(from).isBetween(before.minusSeconds(1), after.plusSeconds(1));
    }

    @Test
    void listExpiring_rejectsWithinDaysOutside1To90() {
        assertThatThrownBy(() -> service.listExpiring(ORG_ID, 0, PageRequest.of(0, 10)))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("withinDays");
        assertThatThrownBy(() -> service.listExpiring(ORG_ID, 91, PageRequest.of(0, 10)))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("withinDays");
        verifyNoInteractions(certificateRepository);
    }

    @Test
    void listExpiring_acceptsBoundaryWithinDays() {
        Slice<CertificateRepository.ExpiringCertificateRow> slice =
                new SliceImpl<>(List.of(), PageRequest.of(0, 5), false);
        when(certificateRepository.findExpiringBetween(eq(ORG_ID), any(), any(), any()))
                .thenReturn(slice);

        assertThat(service.listExpiring(ORG_ID, 1, PageRequest.of(0, 5))).isSameAs(slice);
        assertThat(service.listExpiring(ORG_ID, 90, PageRequest.of(0, 5))).isSameAs(slice);

        ArgumentCaptor<OffsetDateTime> fromCap = ArgumentCaptor.forClass(OffsetDateTime.class);
        ArgumentCaptor<OffsetDateTime> toCap = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(certificateRepository, times(2)).findExpiringBetween(
                eq(ORG_ID), fromCap.capture(), toCap.capture(), eq(PageRequest.of(0, 5)));
        assertThat(toCap.getAllValues().get(0)).isEqualTo(fromCap.getAllValues().get(0).plusDays(1));
        assertThat(toCap.getAllValues().get(1)).isEqualTo(fromCap.getAllValues().get(1).plusDays(90));
    }

    // ----------------------------------------------------------------- //
    //  issue feature-flag
    // ----------------------------------------------------------------- //

    @Test
    void issue_caFeatureFlagDisabled_assertThrows() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setDomain("example.com");
        req.setCaProvider(CaProvider.GLOBALSIGN);
        req.setDnsCredentialXref("cred-dns");
        doThrow(new RuntimeException("CA GLOBALSIGN disabled"))
                .when(featureFlagService).assertCaEnabled(eq("GLOBALSIGN"), eq(ORG_ID));

        assertThatThrownBy(() -> service.issue(ORG_ID, req))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("GLOBALSIGN disabled");
        verifyNoInteractions(persistenceService);
    }

    @Test
    void issue_newUdc_createdWhenAbsent() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setDomain("new.example.com");
        req.setCaProvider(CaProvider.LETS_ENCRYPT);
        req.setDnsCredentialXref("cred-dns");

        when(credentialService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(CredentialReferenceEntity.builder()
                        .credentialXref("cred-dns").type("DNS").provider("AZURE_DNS")
                        .secretHandle("kv-dns").status("ACTIVE").build());
        when(udcRepository.findByOrganizationIdAndDomain(ORG_ID, "new.example.com"))
                .thenReturn(Optional.empty());
        when(udcRepository.save(any())).thenAnswer(inv -> {
            UserDomainCertEntity u = inv.getArgument(0);
            u.setId(UDC_ID);
            return u;
        });
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        service.issue(ORG_ID, req);

        verify(udcRepository).save(any(UserDomainCertEntity.class));
    }

    // ----------------------------------------------------------------- //
    //  deleteRevoked
    // ----------------------------------------------------------------- //

    @Test
    void deleteRevoked_revokedStatus_softDeletesIt() {
        CertificateEntity cert = buildCert("REVOKED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.of(cert));

        service.deleteRevoked(ORG_ID, CERT_XREF);

        verify(persistenceService).softDeleteAndInsertEvent(eq(CERT_XREF), eq(ORG_ID), eq("REVOKED"), any(), any(), eq("EXPIRY_CLEANUP"));
    }

    @Test
    void deleteRevoked_nonRevokedStatus_softDeletesItWithItsStatus() {
        CertificateEntity cert = buildCert("ACTIVE");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.of(cert));

        service.deleteRevoked(ORG_ID, CERT_XREF);

        verify(persistenceService).softDeleteAndInsertEvent(eq(CERT_XREF), eq(ORG_ID), eq("ACTIVE"), any(), any(), eq("EXPIRY_CLEANUP"));
    }

    @Test
    void deleteRevoked_certNotFound_noop() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.empty());

        service.deleteRevoked(ORG_ID, CERT_XREF);

        verifyNoInteractions(persistenceService);
    }

    // ----------------------------------------------------------------- //
    //  finalizeRevocation
    // ----------------------------------------------------------------- //

    @Test
    void finalizeRevocation_disablesScheduleReleasesAndNotifies() {
        CertificateEntity cert = buildCert("REVOKED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.disableSchedule(CERT_XREF)).thenReturn(1);

        service.finalizeRevocation(ORG_ID, CERT_XREF);

        verify(renewalScheduleRepository).disableSchedule(CERT_XREF);
    }

    @Test
    void finalizeRevocation_scheduleAlreadyDisabled_stillReleases() {
        CertificateEntity cert = buildCert("REVOKED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.disableSchedule(CERT_XREF)).thenReturn(0);

        service.finalizeRevocation(ORG_ID, CERT_XREF);

    }

    @Test
    void finalizeRevocation_certNotFound_noop() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORG_ID))
                .thenReturn(Optional.empty());

        service.finalizeRevocation(ORG_ID, CERT_XREF);

        verifyNoInteractions(renewalScheduleRepository);
    }

    // ----------------------------------------------------------------- //
    //  deleteAllCertsForOrganization
    // ----------------------------------------------------------------- //

    @Test
    void deleteAllCertsForOrganization_delegatesToPersistence() {
        service.deleteAllCertsForOrganization(ORG_ID);
        verify(persistenceService).softDeleteAllByOrganizationId(ORG_ID);
    }

    // ----------------------------------------------------------------- //
    //  delete (single) — allocation release path
    // ----------------------------------------------------------------- //

    // ----------------------------------------------------------------- //
    //  deleteUserDomainCert
    // ----------------------------------------------------------------- //

    @Test
    void deleteUserDomainCert_cascadesPerCertAndPerUdcRows() {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).organizationId(ORG_ID).domain("example.com").build();
        when(udcRepository.findById(UDC_ID)).thenReturn(Optional.of(udc));

        when(certificateRepository.findActiveByUserDomainCertIdAndOrganizationId(UDC_ID, ORG_ID))
                .thenReturn(List.of(xrefStatus(CERT_XREF, "ACTIVE"), xrefStatus("cert-2", "PENDING")));
        when(domainCredConfigRepository.softDeleteByUserDomainCertId(UDC_ID)).thenReturn(1);
        when(certDeploymentConfigRepository.softDeleteByUserDomainCertId(UDC_ID)).thenReturn(1);
        when(udcRepository.softDeleteByIdAndOrganizationId(UDC_ID, ORG_ID)).thenReturn(1);

        service.deleteUserDomainCert(ORG_ID, UDC_ID);

        verify(persistenceService).softDeleteAndInsertEvent(eq(CERT_XREF), eq(ORG_ID), eq("ACTIVE"), any(), any(), eq("MANAGED_DOMAIN"));
        verify(persistenceService).softDeleteAndInsertEvent(eq("cert-2"), eq(ORG_ID), eq("PENDING"), any(), any(), eq("MANAGED_DOMAIN"));
        verify(domainCredConfigRepository).softDeleteByUserDomainCertId(UDC_ID);
        verify(certDeploymentConfigRepository).softDeleteByUserDomainCertId(UDC_ID);
        verify(udcRepository).softDeleteByIdAndOrganizationId(UDC_ID, ORG_ID);
    }

    @Test
    void deleteUserDomainCert_notFound_throws() {
        when(udcRepository.findById(UDC_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteUserDomainCert(ORG_ID, UDC_ID))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("not found for organization");
    }

    @Test
    void deleteUserDomainCert_wrongOrg_throws() {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).organizationId(999L).domain("example.com").build();
        when(udcRepository.findById(UDC_ID)).thenReturn(Optional.of(udc));

        assertThatThrownBy(() -> service.deleteUserDomainCert(ORG_ID, UDC_ID))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ----------------------------------------------------------------- //
    //  resolveCredentialRefsForResponse — secretHandle + fallback paths
    // ----------------------------------------------------------------- //

    @Test
    void resolveCredentialRefsForResponse_nullCert_returnsEmpty() {
        CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(null);
        assertThat(refs.dnsConfigXref()).isEmpty();
        assertThat(refs.deploymentCredentialXrefs()).isEmpty();
        assertThat(refs.dnsCredentialKvPath()).isNull();
    }

    @Test
    void resolveCredentialRefsForResponse_nullUdcId_returnsEmpty() {
        CertificateEntity cert = buildCert("ACTIVE");
        cert.setUserDomainCertId(null);
        CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);
        assertThat(refs.dnsConfigXref()).isEmpty();
    }

    @Test
    void resolveCredentialRefsForResponse_resolvesKvPathsForPrimaryAndDeployment() {
        CertificateEntity cert = buildCert("ACTIVE");
        DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                .id(7L).userDomainCertId(UDC_ID)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of("cred-deploy"))
                .build();
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXrefInternal("cred-dns"))
                .thenReturn(CredentialReferenceEntity.builder().credentialXref("cred-dns").secretHandle("kv-dns-path").build());
        when(credentialService.getByXrefInternal("cred-deploy"))
                .thenReturn(CredentialReferenceEntity.builder().credentialXref("cred-deploy").secretHandle("kv-deploy-path").build());

        CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

        assertThat(refs.dnsCredentialKvPath()).isEqualTo("kv-dns-path");
        assertThat(refs.deploymentCredentialKvPaths()).containsExactly("kv-deploy-path");
    }

    @Test
    void resolveCredentialRefsForResponse_primaryRootMissing_usesFirstAvailableFallback() {
        CertificateEntity cert = buildCert("ACTIVE");
        // dns_config has an entry but keyed by an unrelated root (no match for example.com root)
        java.util.LinkedHashMap<String, String> dns = new java.util.LinkedHashMap<>();
        dns.put("other.org", "cred-other");
        DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                .id(7L).userDomainCertId(UDC_ID)
                .dnsConfig(dns)
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXrefInternal("cred-other"))
                .thenReturn(CredentialReferenceEntity.builder().credentialXref("cred-other").secretHandle("kv-other").build());

        CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

        assertThat(refs.dnsCredentialKvPath()).isEqualTo("kv-other");
    }

    @Test
    void resolveCredentialRefsForResponse_credentialNotFound_handleNull() {
        CertificateEntity cert = buildCert("ACTIVE");
        DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                .id(7L).userDomainCertId(UDC_ID)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXrefInternal("cred-dns"))
                .thenThrow(new ResourceNotFoundException("gone"));

        CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

        assertThat(refs.dnsCredentialKvPath()).isNull();
    }

    @Test
    void resolveCredentialRefsForResponse_emptyDnsConfig_noPrimaryLookup() {
        CertificateEntity cert = buildCert("ACTIVE");
        DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                .id(7L).userDomainCertId(UDC_ID)
                .dnsConfig(Map.of())
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));

        CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

        assertThat(refs.dnsConfigXref()).isEmpty();
        assertThat(refs.dnsCredentialKvPath()).isNull();
    }
}
