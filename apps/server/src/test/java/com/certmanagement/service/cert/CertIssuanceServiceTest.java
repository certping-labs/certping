// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.CertDeployRequest;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.CertRenewalRequest;
import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.dto.credconfig.KubernetesDeploymentConfigRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertIssuanceCommand;
import com.certmanagement.messaging.model.CertRenewalCommand;
import com.certmanagement.messaging.model.CertRevocationCommand;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.deployment.DeploymentTrackingService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertIssuanceServiceTest {


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
    private long idCounter = 100;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private static final Long   ORGANIZATION_ID   = 1L;
    private static final Long   UDC_ID      = 2L;
    private static final Long   CONFIG_ID   = 3L;
    private static final String CERT_XREF   = "cert-abc123";
    private static final String DNS_XREF    = "cred-dns";
        private static final String SAN_DNS_XREF = "cred-dns-san";
    private static final String ACME_XREF   = "cred-acme";
    private static final String DEPLOY_XREF = "cred-deploy";

    @BeforeEach
    void setUp() {
        service = new CertIssuanceService(
                certificateRepository,
                renewalScheduleRepository,
                domainCredConfigRepository,
                certDeploymentConfigRepository,
                udcRepository,
                credentialService,
                domainCredConfigService,
                persistenceService,
                publisher,
                certificateStatusValidator,
                deploymentExecutionService,
                kubernetesDeploymentConfigResolver,
                certDeploymentConfigService,
                renewalDraftHelper,
                featureFlagService,
                orgTypeResolver);
        lenient().when(orgTypeResolver.resolve(any(Long.class))).thenReturn("B2B");
    }

    // ================================================================== //
    //  issue()
    // ================================================================== //

    @Test
    void issue_happyPath_persistsAndPublishesIssuanceCommand() {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        CertificateEntity savedCert = buildCert("PENDING");
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(savedCert);

        CertificateEntity result = service.issue(ORGANIZATION_ID, issuanceRequest());

        assertThat(result.getStatus()).isEqualTo("PENDING");
        verify(persistenceService).persistIssuance(any(), any(), any(), any(), any());
        verify(publisher).publishIssuance(any());
    }

    @Test
    void issue_givesEachCertificateARandomUuidXref() {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any())).thenReturn(buildCert("PENDING"));

        service.issue(ORGANIZATION_ID, issuanceRequest());
        service.issue(ORGANIZATION_ID, issuanceRequest());

        ArgumentCaptor<CertificateEntity> certs = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(persistenceService, org.mockito.Mockito.times(2)).persistIssuance(certs.capture(), any(), any(), any(), any());
        List<String> xrefs = certs.getAllValues().stream().map(CertificateEntity::getCertificateXref).toList();
        assertThat(xrefs).allMatch(x -> x.matches("cert-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
                .doesNotHaveDuplicates();
    }

    @Test
    void issue_aFailedPersist_rollsBackTheNewUserDomainCertRow() {
        stubDnsCredential(DNS_XREF);
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "example.com")).thenReturn(Optional.empty());
        when(udcRepository.save(any())).thenReturn(buildUdc());
        org.springframework.transaction.PlatformTransactionManager txManager =
                org.mockito.Mockito.mock(org.springframework.transaction.PlatformTransactionManager.class);
        org.springframework.transaction.TransactionStatus tx =
                org.mockito.Mockito.mock(org.springframework.transaction.TransactionStatus.class);
        when(txManager.getTransaction(any())).thenReturn(tx);
        service.setTransactionTemplate(new org.springframework.transaction.support.TransactionTemplate(txManager));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenThrow(new org.springframework.dao.DataIntegrityViolationException("duplicate key value"));

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, issuanceRequest()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);

        // The user_domain_certificate insert ran inside the transaction that was rolled back, not committed.
        org.mockito.InOrder order = org.mockito.Mockito.inOrder(txManager, udcRepository);
        order.verify(txManager).getTransaction(any());
        order.verify(udcRepository).save(any());
        order.verify(txManager).rollback(tx);
        verify(txManager, never()).commit(any());
        verify(publisher, never()).publishIssuance(any());
    }

    @Test
    void issue_aSanEntryWithNamesUnderTwoDomains_isRefusedBeforeAnythingIsReadReservedOrSaved() {
        CertIssuanceRequest request = issuanceRequest();
        request.setSan(true);
        CertIssuanceRequest.SanDomainEntry mixed = new CertIssuanceRequest.SanDomainEntry();
        mixed.setPatterns(List.of("www.bar.com", "api.baz.org"));
        mixed.setDnsCredentialXref(SAN_DNS_XREF);
        request.setSanDomainEntries(List.of(mixed));

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, request))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class)
                .hasMessage("Each additional domain group must use names under one domain.");

        org.mockito.Mockito.verifyNoInteractions(credentialService, persistenceService, publisher);
    }

    @Test
    void issue_dnsCredentialWrongType_throwsBadRequest() {
        when(credentialService.getByXref(ORGANIZATION_ID, DNS_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV", "kv-path"));

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, issuanceRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be type DNS")
                .hasMessageContaining("DEPLOYMENT");
    }

    @Test
    void issue_inactiveCredential_throwsBadRequest() {
        when(credentialService.getByXref(ORGANIZATION_ID, DNS_XREF))
                .thenReturn(buildInactiveCredential("DNS", "AZURE_DNS", "kv-path"));

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, issuanceRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not ACTIVE");
    }

    @Test
    void issue_withDeploymentTargets_validatesAndStores() {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV", "kv-path-deploy"));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        CertIssuanceRequest req = issuanceRequest();
        req.setDeploymentTargets(List.of(DEPLOY_XREF));

        CertificateEntity result = service.issue(ORGANIZATION_ID, req);

        assertThat(result).isNotNull();
        // credConfig should have the deployment target
        ArgumentCaptor<DomainCredentialConfigEntity> credConfigCaptor =
                ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(persistenceService).persistIssuance(any(), credConfigCaptor.capture(), any(), any(), any());
        assertThat(credConfigCaptor.getValue().getDeploymentTargets()).contains(DEPLOY_XREF);
    }

    @Test
    void issue_withKubernetesDeploymentTargetConfig_upsertsConfigWhenAutoDeployEnabled() throws Exception {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        CredentialReferenceEntity deployCred = buildCredential("DEPLOYMENT", "KUBERNETES_SECRETS", "kv-path-deploy");
        deployCred.setId(55L);
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF)).thenReturn(deployCred);
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        CertIssuanceRequest.DeploymentTargetConfigEntry targetConfig = new CertIssuanceRequest.DeploymentTargetConfigEntry();
        targetConfig.setDeploymentCredentialXref(DEPLOY_XREF);
        KubernetesDeploymentConfigRequest config = new KubernetesDeploymentConfigRequest();
        config.setUseDefault(false);
        config.setNsSecretMap(objectMapper.readTree("[{\"dev\":\"example-dev-tls\"}]"));
        targetConfig.setConfig(config);

        CertIssuanceRequest req = issuanceRequest();
        req.setDeploymentTargets(List.of(DEPLOY_XREF));
        req.setDeploymentTargetConfigs(List.of(targetConfig));

        service.issue(ORGANIZATION_ID, req);

        verify(kubernetesDeploymentConfigResolver).resolveOrUpsert(
                eq(ORGANIZATION_ID),
                eq(UDC_ID),
                eq(deployCred),
                eq(false),
                any(),
                contains(DEPLOY_XREF));
    }

    @Test
    void issue_withDeploymentTargetConfigButNoDeploymentTargets_ignoresConfig() throws Exception {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        CertIssuanceRequest.DeploymentTargetConfigEntry targetConfig = new CertIssuanceRequest.DeploymentTargetConfigEntry();
        targetConfig.setDeploymentCredentialXref(DEPLOY_XREF);
        KubernetesDeploymentConfigRequest config = new KubernetesDeploymentConfigRequest();
        config.setUseDefault(false);
        config.setNsSecretMap(objectMapper.readTree("[{\"dev\":\"example-dev-tls\"}]"));
        targetConfig.setConfig(config);

        CertIssuanceRequest req = issuanceRequest();
        req.setDeploymentTargets(List.of());
        req.setDeploymentTargetConfigs(List.of(targetConfig));

        service.issue(ORGANIZATION_ID, req);

        verify(kubernetesDeploymentConfigResolver, never()).resolveOrUpsert(anyLong(), anyLong(), any(), any(), any(), anyString());
    }

        @Test
        void issue_withSanEntries_persistsSanDomains() {
                stubDnsCredential(DNS_XREF);
                stubDnsCredential(SAN_DNS_XREF);
                stubUdcLookup();
                when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                                .thenReturn(buildCert("PENDING"));

                CertIssuanceRequest req = issuanceRequest();
                req.setSan(true);

                CertIssuanceRequest.SanDomainEntry sanEntry = new CertIssuanceRequest.SanDomainEntry();
                sanEntry.setPatterns(List.of("*.api.example.com", "api.example.com"));
                sanEntry.setDnsCredentialXref(SAN_DNS_XREF);
                req.setSanDomainEntries(List.of(sanEntry));

                service.issue(ORGANIZATION_ID, req);

                ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
                verify(persistenceService).persistIssuance(certCaptor.capture(), any(), any(), any(), any());
                assertThat(certCaptor.getValue().getSanDomains())
                                .contains("*.api.example.com", "api.example.com");
        }

    @Test
    void issue_primaryWildcardTrue_withMixedSanPatterns_publishesExpectedCommandShape() {
        stubDnsCredential(DNS_XREF);
        stubDnsCredential(SAN_DNS_XREF);
        UserDomainCertEntity udc = buildUdc();
        udc.setDomain("xyz.com");
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "xyz.com"))
                .thenReturn(Optional.of(udc));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        CertIssuanceRequest req = issuanceRequest();
        req.setDomain("xyz.com");
        req.setWildcard(true);
        req.setSan(true);

        CertIssuanceRequest.SanDomainEntry sanEntry = new CertIssuanceRequest.SanDomainEntry();
        sanEntry.setDnsCredentialXref(SAN_DNS_XREF);
        sanEntry.setPatterns(List.of("*.xyz.com", "v2.api.xyz.com", "api.xyz.com"));
        req.setSanDomainEntries(List.of(sanEntry));

        service.issue(ORGANIZATION_ID, req);

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());
        CertIssuanceCommand cmd = cmdCaptor.getValue();

        assertThat(cmd.getDomain()).isEqualTo("xyz.com");
        assertThat(cmd.getWildcard()).isTrue();
        assertThat(cmd.getSan()).isTrue();
        assertThat(cmd.getSanDomainEntries()).hasSize(1);
        // api.xyz.com is covered by *.xyz.com (one-label rule) → correctly pruned before publish
        assertThat(cmd.getSanDomainEntries().get(0).getPatterns())
                .containsExactly("*.xyz.com", "v2.api.xyz.com");
    }

    @Test
    void issue_digicert_sendsAndStoresTheRequestedValidity() {
        stubDnsCredential(DNS_XREF);
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "example.com"))
                .thenReturn(Optional.of(buildUdc()));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));
        stubOptionalCredential("cred-ca", "CA", "DIGICERT");
        CertIssuanceRequest req = issuanceRequest();
        req.setCaProvider(CaProvider.DIGICERT);
        req.setCaCredentialXref("cred-ca");
        req.setValidityDays(199);

        service.issue(ORGANIZATION_ID, req);

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());
        assertThat(cmdCaptor.getValue().getValidityDays()).isEqualTo(199);
        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(persistenceService).persistIssuance(certCaptor.capture(), any(), any(), any(), any());
        assertThat(certCaptor.getValue().getRequestedValidityDays()).isEqualTo(199);
    }

    @Test
    void issue_primaryWildcardFalse_withMixedSanPatterns_publishesExpectedCommandShape() {
        stubDnsCredential(DNS_XREF);
        stubDnsCredential(SAN_DNS_XREF);
        UserDomainCertEntity udc = buildUdc();
        udc.setDomain("xyz.com");
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "xyz.com"))
                .thenReturn(Optional.of(udc));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        CertIssuanceRequest req = issuanceRequest();
        req.setDomain("xyz.com");
        req.setWildcard(false);
        req.setSan(true);

        CertIssuanceRequest.SanDomainEntry sanEntry = new CertIssuanceRequest.SanDomainEntry();
        sanEntry.setDnsCredentialXref(SAN_DNS_XREF);
        sanEntry.setPatterns(List.of("*.xyz.com", "v2.api.xyz.com", "api.xyz.com"));
        req.setSanDomainEntries(List.of(sanEntry));

        service.issue(ORGANIZATION_ID, req);

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());
        CertIssuanceCommand cmd = cmdCaptor.getValue();

        assertThat(cmd.getDomain()).isEqualTo("xyz.com");
        assertThat(cmd.getWildcard()).isFalse();
        assertThat(cmd.getSan()).isTrue();
        assertThat(cmd.getSanDomainEntries()).hasSize(1);
        // api.xyz.com is covered by *.xyz.com (one-label rule) → correctly pruned before publish
        assertThat(cmd.getSanDomainEntries().get(0).getPatterns())
                .containsExactly("*.xyz.com", "v2.api.xyz.com");
    }

    @Test
    void issue_deploymentTargetWrongType_throwsBadRequest() {
        stubDnsCredential(DNS_XREF);
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DNS", "AZURE_DNS", "kv-path-deploy")); // wrong type

        CertIssuanceRequest req = issuanceRequest();
        req.setDeploymentTargets(List.of(DEPLOY_XREF));

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("deploymentTargets")
                .hasMessageContaining("DEPLOYMENT");
    }

    @Test
    void issue_digicertWithItsCaCredential_sendsTheKeyHandleToTheAgent() {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        stubOptionalCredential("cred-ca", "CA", "DIGICERT");
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));
        CertIssuanceRequest req = issuanceRequest();
        req.setCaProvider(CaProvider.DIGICERT);
        req.setCaCredentialXref("cred-ca");

        service.issue(ORGANIZATION_ID, req);

        ArgumentCaptor<CertIssuanceCommand> cmd = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmd.capture());
        assertThat(cmd.getValue().getCaCredentialHandle()).isEqualTo("https://kv.vault.azure.net/secrets/cred-ca");
    }

    @Test
    void issue_digicertWithoutACaCredential_isRefusedBeforeAnythingIsSaved() {
        stubDnsCredential(DNS_XREF);
        CertIssuanceRequest req = issuanceRequest();
        req.setCaProvider(CaProvider.DIGICERT);

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("DigiCert API key");
        verifyNoInteractions(persistenceService, publisher);
    }

    @ParameterizedTest
    @CsvSource({"DNS,CERTPING", "DEPLOYMENT,AWS_ACM", "CA,GLOBALSIGN"})
    void issue_digicertWithAnotherKindOfCredentialAsTheCaKey_isRefused(String type, String provider) {
        stubDnsCredential(DNS_XREF);
        stubOptionalCredential("cred-other", type, provider);
        CertIssuanceRequest req = issuanceRequest();
        req.setCaProvider(CaProvider.DIGICERT);
        req.setCaCredentialXref("cred-other");

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be a DIGICERT CA credential");
        verifyNoInteractions(persistenceService, publisher);
    }

    @Test
    void issue_letsEncryptWithADigiCertKey_isRefused() {
        stubDnsCredential(DNS_XREF);
        stubOptionalCredential("cred-ca", "CA", "DIGICERT");
        CertIssuanceRequest req = issuanceRequest();
        req.setCaCredentialXref("cred-ca");

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be a LETS_ENCRYPT CA credential");
    }

    @Test
    void issue_buildsDnsConfigMap_withPrimaryDomainEntry() {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        service.issue(ORGANIZATION_ID, issuanceRequest());

        ArgumentCaptor<DomainCredentialConfigEntity> captor =
                ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(persistenceService).persistIssuance(any(), captor.capture(), any(), any(), any());
        assertThat(captor.getValue().getDnsConfig()).containsKey("example.com");
        assertThat(captor.getValue().getDnsConfig()).containsValue(DNS_XREF);
    }

    @Test
    void issue_publishFails_marksIssuanceFailedAndThrowsServiceUnavailable() {
        stubDnsCredential(DNS_XREF);
        stubUdcLookup();
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));
        doThrow(new RuntimeException("message queue unavailable"))
                .when(publisher).publishIssuance(any());

        assertThatThrownBy(() -> service.issue(ORGANIZATION_ID, issuanceRequest()))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("marked FAILED");

        verify(persistenceService).markIssuancePublishFailed(
                any(), eq(ORGANIZATION_ID), any(), any(), contains("message queue unavailable"));
        verify(persistenceService).persistIssuance(any(), any(), any(), any(), any());
    }

    @Test
    void list_withPageAndSize_appliesUpdatedAtDescendingSort() {
        Page<CertificateEntity> emptyPage = new PageImpl<>(List.of());
        when(certificateRepository.findLatestByOrganizationAndFilters(
                eq(ORGANIZATION_ID), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(emptyPage);

        service.list(ORGANIZATION_ID, null, null, 0, 20);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(certificateRepository).findLatestByOrganizationAndFilters(
                eq(ORGANIZATION_ID), isNull(), isNull(), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("updatedAt");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(Sort.Direction.DESC);
    }

    @Test
    void list_withUnsortedPageable_defaultsToUpdatedAtDescendingSort() {
        Page<CertificateEntity> emptyPage = new PageImpl<>(List.of());
        when(certificateRepository.findLatestByOrganizationAndFilters(
                eq(ORGANIZATION_ID), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(emptyPage);

        service.list(ORGANIZATION_ID, null, null, PageRequest.of(1, 10));

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(certificateRepository).findLatestByOrganizationAndFilters(
                eq(ORGANIZATION_ID), isNull(), isNull(), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("updatedAt");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(Sort.Direction.DESC);
    }

    @Test
    void list_withStatusAndDomain_normalizesStatusAndPassesFilters() {
        Page<CertificateEntity> emptyPage = new PageImpl<>(List.of());
        when(certificateRepository.findLatestByOrganizationAndFilters(
                eq(ORGANIZATION_ID), eq("ACTIVE"), eq("%example%"), any(Pageable.class)))
                .thenReturn(emptyPage);

        service.list(ORGANIZATION_ID, "active", "example", 0, 20);

        verify(certificateRepository).findLatestByOrganizationAndFilters(
                eq(ORGANIZATION_ID), eq("ACTIVE"), eq("%example%"), any(Pageable.class));
    }

    @Test
        void history_withPageAndSize_appliesUpdatedAtDescendingSort() {
        Long historyUdcId = 301L;
        Page<CertificateEntity> emptyPage = new PageImpl<>(List.of());
        when(certificateRepository.findHistoryByOrganizationAndUserDomainCertId(
                eq(ORGANIZATION_ID), eq(historyUdcId), any(Pageable.class)))
                .thenReturn(emptyPage);

        service.history(ORGANIZATION_ID, historyUdcId, 0, 20);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(certificateRepository).findHistoryByOrganizationAndUserDomainCertId(
                eq(ORGANIZATION_ID), eq(historyUdcId), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("updatedAt");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(Sort.Direction.DESC);
    }

        @Test
        void history_includesFailedRowsWhenRepositoryReturnsThem() {
                Long historyUdcId = 301L;
                CertificateEntity failed = buildCert("FAILED");
                CertificateEntity active = buildCert("ACTIVE");
                active.setCertificateXref("cert-2");

                Page<CertificateEntity> page = new PageImpl<>(List.of(failed, active));
                when(certificateRepository.findHistoryByOrganizationAndUserDomainCertId(
                                eq(ORGANIZATION_ID), eq(historyUdcId), any(Pageable.class)))
                                .thenReturn(page);

                Page<CertificateEntity> result = service.history(ORGANIZATION_ID, historyUdcId, 0, 20);

                assertThat(result.getContent()).hasSize(2);
                assertThat(result.getContent()).extracting(CertificateEntity::getStatus)
                                .containsExactly("FAILED", "ACTIVE");
        }

    // ================================================================== //
    //  delete()
    // ================================================================== //

    @Test
    void delete_happyPath_usesPersistenceSoftDeleteWithEvent() {
        CertificateEntity cert = buildCert("FAILED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(persistenceService.softDeleteAndInsertEvent(eq(CERT_XREF), eq(ORGANIZATION_ID), eq("FAILED"), any(), any()))
                .thenReturn(1);

        service.delete(ORGANIZATION_ID, CERT_XREF);

        verify(persistenceService).softDeleteAndInsertEvent(eq(CERT_XREF), eq(ORGANIZATION_ID), eq("FAILED"), any(), any());
    }

    @Test
    void delete_whenNoRowsUpdated_throwsResourceNotFound() {
        CertificateEntity cert = buildCert("FAILED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(persistenceService.softDeleteAndInsertEvent(eq(CERT_XREF), eq(ORGANIZATION_ID), eq("FAILED"), any(), any()))
                .thenReturn(0);

        assertThatThrownBy(() -> service.delete(ORGANIZATION_ID, CERT_XREF))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("not found or already deleted");
    }

    // ================================================================== //
    //  renew()
    // ================================================================== //

    @Test
    void renew_happyPath_persistsAndPublishesRenewalCommand() {
        CertificateEntity activeCert = buildCert("ACTIVE");
                activeCert.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-old");
        stubCertLookup(activeCert);
        stubScheduleAndCredConfig();
        stubUdcById();
        stubDnsCredential(DNS_XREF);
        when(persistenceService.persistRenewal(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new CertPersistenceService.RenewalPersistResult(activeCert, buildCert("PENDING")));

        CertificateEntity result = service.renew(ORGANIZATION_ID, CERT_XREF, null);

        assertThat(result).isNotNull();
        verify(persistenceService).persistRenewal(eq(activeCert), any(), any(), isNull(), eq("ACTIVE"), any(), any());
                ArgumentCaptor<CertRenewalCommand> cmdCaptor = ArgumentCaptor.forClass(CertRenewalCommand.class);
                verify(publisher).publishRenewal(cmdCaptor.capture());
                CertRenewalCommand cmd = cmdCaptor.getValue();
                assertThat(cmd.getCertificateXref()).isNotEqualTo(CERT_XREF);
                assertThat(cmd.getCertSecretHandle()).contains("/secrets/");
                assertThat(cmd.getCertSecretHandle()).contains(cmd.getCertificateXref());
    }

    @Test
    void renew_ofACustomerHeldKey_isRefusedWithANewRequestSuggested() {
        CertificateEntity activeCert = buildCert("ACTIVE");
        activeCert.setKeyCustody(com.certmanagement.enums.KeyCustody.CUSTOMER_HELD);
        stubCertLookup(activeCert);

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("request a new certificate");
        verify(persistenceService, never()).persistRenewal(any(), any(), any(), any(), any(), any(), any());
        verify(publisher, never()).publishRenewal(any());
    }

    @Test
    void renew_withDeploymentTargetsOverride_updatesCredConfig() {
        CertificateEntity activeCert = buildCert("ACTIVE");
        stubCertLookup(activeCert);
        stubScheduleAndCredConfig();
        stubUdcById();
        stubDnsCredential(DNS_XREF);
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV", "kv-deploy"));
        when(persistenceService.persistRenewal(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new CertPersistenceService.RenewalPersistResult(activeCert, buildCert("PENDING")));

        CertRenewalRequest req = new CertRenewalRequest();
        req.setDeploymentTargets(List.of(DEPLOY_XREF));

        service.renew(ORGANIZATION_ID, CERT_XREF, req);

        verify(persistenceService).persistRenewal(eq(activeCert), any(), any(), eq(List.of(DEPLOY_XREF)),
                eq("ACTIVE"), any(), any());
    }

    @Test
    void renew_certNotFound_throwsResourceNotFound() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining(CERT_XREF);
    }

    @Test
    void renew_alreadyRenewing_throwsBadRequest() {
        stubCertLookup(buildCert("RENEWING"));

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("cannot be renewed in current state: RENEWING");

        verify(persistenceService, never()).persistRenewal(any(), any(), any(), any(), any(), any(), any());
        verify(publisher, never()).publishRenewal(any());
    }

    @Test
    void renew_alreadyPending_throwsDuplicateResource() {
        stubCertLookup(buildCert("PENDING"));

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("issuance in progress");
    }

    @Test
    void renew_noSchedule_throwsResourceNotFound() {
        stubCertLookup(buildCert("ACTIVE"));
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("renewal schedule");
    }

    @Test
    void renew_primaryDnsCredNotInConfig_throwsResourceNotFound() {
        CertificateEntity cert = buildCert("ACTIVE");
        stubCertLookup(cert);

        RenewalScheduleEntity schedule = buildSchedule();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));

        // dns_config with no entry for "example.com"
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID).userDomainCertId(UDC_ID)
                .dnsConfig(new LinkedHashMap<>())  // empty!
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigService.getById(CONFIG_ID)).thenReturn(credConfig);
        stubUdcById();

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("DNS credential");
    }

    @Test
    void renew_publishFails_revertsStatusAndThrowsServiceUnavailable() {
        CertificateEntity cert = buildCert("ACTIVE");
        stubCertLookup(cert);
        stubScheduleAndCredConfig();
        stubUdcById();
        stubDnsCredential(DNS_XREF);
        when(persistenceService.persistRenewal(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new CertPersistenceService.RenewalPersistResult(cert, buildCert("PENDING")));
        doThrow(new RuntimeException("publish refused", new IllegalArgumentException("message rejected before sending")))
                .when(publisher).publishRenewal(any());

        assertThatThrownBy(() -> service.renew(ORGANIZATION_ID, CERT_XREF, null))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("reverted to ACTIVE");

        verify(persistenceService).markRenewalPublishFailed(
                eq(CERT_XREF), any(), eq(ORGANIZATION_ID), eq("ACTIVE"), any(), any(),
                contains("publish refused"));
    }

    @Test
    void renew_aPublishThatMayHaveBeenSent_isAcceptedAndLeftInFlight() {
        CertificateEntity cert = buildCert("ACTIVE");
        stubCertLookup(cert);
        stubScheduleAndCredConfig();
        stubUdcById();
        stubDnsCredential(DNS_XREF);
        when(persistenceService.persistRenewal(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new CertPersistenceService.RenewalPersistResult(cert, buildCert("PENDING")));
        doThrow(new RuntimeException("queue timeout")).when(publisher).publishRenewal(any());

        assertThat(service.renew(ORGANIZATION_ID, CERT_XREF, null)).isSameAs(cert);

        verify(persistenceService, never()).markRenewalPublishFailed(any(), any(), any(), any(), any(), any(), any());
    }

    // ================================================================== //
    //  deploy()
    // ================================================================== //

    @Test
    void deploy_happyPath_persistsAndPublishesDeploymentCommand() {
        CertificateEntity cert = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        stubDeployCredential(DEPLOY_XREF, "AZURE_KV");

        CertificateEntity result = service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest());

        assertThat(result).isNotNull();
        verify(deploymentExecutionService).dispatchSingle(
                eq(ORGANIZATION_ID), eq(cert), eq(cert.getCertSecretHandle()),
                eq(DEPLOY_XREF), any(CredentialReferenceEntity.class),
                anyString(), nullable(String.class), eq("MANUAL"), isNull());
    }

    @Test
    void deploy_renewingAndStillValid_allowsDeployment() {
        CertificateEntity cert = buildActiveCertWithKvPath();
        cert.setStatus("RENEWING");
        cert.setValidTo(OffsetDateTime.now().plusDays(5));

        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        stubDeployCredential(DEPLOY_XREF, "AZURE_KV");

        CertificateEntity result = service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest());

        assertThat(result).isNotNull();
        verify(deploymentExecutionService).dispatchSingle(
                eq(ORGANIZATION_ID), eq(cert), eq(cert.getCertSecretHandle()),
                eq(DEPLOY_XREF), any(CredentialReferenceEntity.class),
                anyString(), nullable(String.class), eq("MANUAL"), isNull());
    }

    @Test
    void deploy_renewingButExpired_throwsBadRequest() {
        CertificateEntity cert = buildActiveCertWithKvPath();
        cert.setStatus("RENEWING");
        cert.setValidTo(OffsetDateTime.now().minusMinutes(1));

        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("validTo")
                .hasMessageContaining("in the past");
    }

    @Test
    void deploy_certNotActive_throwsBadRequest() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(buildCert("PENDING")));

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be ACTIVE, RENEWING or RENEW_SUCCESS")
                .hasMessageContaining("PENDING");
    }

    @Test
    void deploy_ofACustomerHeldKey_isRefused() {
        CertificateEntity cert = buildActiveCertWithKvPath();
        cert.setKeyCustody(com.certmanagement.enums.KeyCustody.CUSTOMER_HELD);
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("customer holds its private key");
        verify(publisher, never()).publishDeployment(any());
    }

    @Test
    void deploy_missingCertSecretHandle_throwsBadRequest() {
        CertificateEntity cert = buildCert("ACTIVE");   // certSecretHandle is null
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("no certSecretHandle");
    }

    @Test
    void deploy_credentialTypeNotDeployment_throwsBadRequest() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(buildActiveCertWithKvPath()));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DNS", "AZURE_KV", "kv-path"));

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be type DEPLOYMENT");
    }

    @Test
    void deploy_credentialProviderMismatch_throwsBadRequest() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(buildActiveCertWithKvPath()));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AWS_ACM", "kv-path"));

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("provider matches the deployment target");
    }

    @Test
    void deploy_publishFails_propagatesServiceUnavailable() {
        CertificateEntity cert = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        stubDeployCredential(DEPLOY_XREF, "AZURE_KV");
        doThrow(new ServiceUnavailableException("marked as PUBLISH_FAILED — please retry."))
                .when(deploymentExecutionService).dispatchSingle(any(), any(), any(), any(), any(), any(), any(), any(), any());

        assertThatThrownBy(() -> service.deploy(ORGANIZATION_ID, CERT_XREF, deployRequest()))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("marked as PUBLISH_FAILED");
    }

    @Test
    void deploy_kubernetesUseDefault_resolvesStoredConfigBeforeDispatch() {
        CertificateEntity cert = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        stubDeployCredential(DEPLOY_XREF, "KUBERNETES_SECRETS");
        when(kubernetesDeploymentConfigResolver.resolveOrUpsert(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), eq(true), isNull(), anyString()))
                .thenReturn("{\"clusterName\":\"prod\"}");

        CertDeployRequest request = new CertDeployRequest();
        request.setDeploymentCredentialXref(DEPLOY_XREF);
        request.setTargetType(TargetType.KUBERNETES_SECRETS);
        request.setUseDefault(true);

        service.deploy(ORGANIZATION_ID, CERT_XREF, request);

        verify(kubernetesDeploymentConfigResolver).resolveOrUpsert(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), eq(true), isNull(), anyString());
        verify(deploymentExecutionService).dispatchSingle(
                eq(ORGANIZATION_ID), eq(cert), eq(cert.getCertSecretHandle()),
                eq(DEPLOY_XREF), any(CredentialReferenceEntity.class),
                anyString(), nullable(String.class), eq("MANUAL"), contains("clusterName"));
    }

    @Test
    void deploy_kubernetesExplicitConfig_upsertsBeforeDispatch() throws Exception {
        CertificateEntity cert = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        stubDeployCredential(DEPLOY_XREF, "KUBERNETES_SECRETS");
        when(kubernetesDeploymentConfigResolver.resolveOrUpsert(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), isNull(), any(), anyString()))
                .thenReturn("{\"clusterName\":\"prod\",\"nsMaps\":[{\"dev\":\"example-dev-tls\"}]}");

        CertDeployRequest request = new CertDeployRequest();
        request.setDeploymentCredentialXref(DEPLOY_XREF);
        request.setTargetType(TargetType.KUBERNETES_SECRETS);
        request.setConfig(objectMapper.readTree("[{\"dev\":\"example-dev-tls\"}]"));

        service.deploy(ORGANIZATION_ID, CERT_XREF, request);

        verify(kubernetesDeploymentConfigResolver).resolveOrUpsert(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), isNull(), any(), anyString());
        verify(deploymentExecutionService).dispatchSingle(
                eq(ORGANIZATION_ID), eq(cert), eq(cert.getCertSecretHandle()),
                eq(DEPLOY_XREF), any(CredentialReferenceEntity.class),
                anyString(), nullable(String.class), eq("MANUAL"), contains("example-dev-tls"));
    }

    @Test
    void deploy_kubernetesUseDefault_ignoresProvidedConfigAndUsesStoredDefault() throws Exception {
        CertificateEntity cert = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        stubDeployCredential(DEPLOY_XREF, "KUBERNETES_SECRETS");
        when(kubernetesDeploymentConfigResolver.resolveOrUpsert(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), eq(true), any(), anyString()))
                .thenReturn("{\"clusterName\":\"prod\",\"authProvider\":\"AWS\",\"nsMaps\":[{\"dev\":\"default-secret\"}]}");

        CertDeployRequest request = new CertDeployRequest();
        request.setDeploymentCredentialXref(DEPLOY_XREF);
        request.setTargetType(TargetType.KUBERNETES_SECRETS);
        request.setUseDefault(true);
        request.setConfig(objectMapper.readTree("[{\"dev\":\"should-be-ignored\"}]"));

        service.deploy(ORGANIZATION_ID, CERT_XREF, request);

        verify(kubernetesDeploymentConfigResolver).resolveOrUpsert(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), eq(true), any(), anyString());
        verify(deploymentExecutionService).dispatchSingle(
                eq(ORGANIZATION_ID), eq(cert), eq(cert.getCertSecretHandle()),
                eq(DEPLOY_XREF), any(CredentialReferenceEntity.class),
                anyString(), nullable(String.class), eq("MANUAL"), contains("default-secret"));
    }

        // ================================================================== //
        //  resolveCredentialRefsForResponse()
        // ================================================================== //

        @Test
        void resolveCredentialRefsForResponse_enabledAndEligible_returnsRefs() {
                CertificateEntity cert = buildCert("ACTIVE");

                DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                                .id(CONFIG_ID)
                                .userDomainCertId(UDC_ID)
                                .dnsConfig(Map.of("example.com", DNS_XREF))
                                .deploymentTargets(List.of(DEPLOY_XREF))
                                .build();
                when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));

                CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

                assertThat(refs.dnsConfigXref()).containsEntry("example.com", DNS_XREF);
                assertThat(refs.deploymentCredentialXrefs()).containsExactly(DEPLOY_XREF);
        }

        @Test
        void resolveCredentialRefsForResponse_missingDomainCredentialConfig_returnsEmptyRefs() {
                CertificateEntity cert = buildCert("ACTIVE");

                when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

                CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

                assertThat(refs.dnsConfigXref()).isEmpty();
                assertThat(refs.deploymentCredentialXrefs()).isEmpty();
                verify(domainCredConfigRepository).findByUserDomainCertId(UDC_ID);
        }

        @Test
        void resolveCredentialRefsForResponse_statusDoesNotGateLookup_returnsConfigWhenPresent() {
                CertificateEntity cert = buildCert("FAILED");

                DomainCredentialConfigEntity config = DomainCredentialConfigEntity.builder()
                                .id(CONFIG_ID)
                                .userDomainCertId(UDC_ID)
                                .dnsConfig(Map.of("example.com", DNS_XREF))
                                .deploymentTargets(List.of(DEPLOY_XREF))
                                .build();
                when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));

                CertIssuanceService.CredentialRefs refs = service.resolveCredentialRefsForResponse(cert);

                assertThat(refs.dnsConfigXref()).containsEntry("example.com", DNS_XREF);
                assertThat(refs.deploymentCredentialXrefs()).containsExactly(DEPLOY_XREF);
                verify(domainCredConfigRepository).findByUserDomainCertId(UDC_ID);
        }

    // ================================================================== //
    //  revoke()
    // ================================================================== //

    @Test
    void revoke_happyPath_persistsRevokingAndPublishesRevocationCommand() {
        CertificateEntity active = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(active));

        CertificateEntity revoking = buildActiveCertWithKvPath();
        revoking.setStatus("REVOKING");
        revoking.setSerialNumber("8A1B2C");
        when(persistenceService.persistRevocation(
                eq(CERT_XREF), eq(ORGANIZATION_ID), eq("ACTIVE"), any(), any(), any()))
                .thenReturn(Optional.of(revoking));

        RevokeRequest req = new RevokeRequest();
        GatewayRequestContext.set(123, ORGANIZATION_ID.toString(), "req-test", "user@example.com");

        CertificateEntity result;
        try {
            result = service.revoke(ORGANIZATION_ID, CERT_XREF, req);
        } finally {
            GatewayRequestContext.clear();
        }

        assertThat(result.getStatus()).isEqualTo("REVOKING");
        verify(persistenceService).persistRevocation(
                eq(CERT_XREF), eq(ORGANIZATION_ID), eq("ACTIVE"), eq(req), any(), any());

        ArgumentCaptor<CertRevocationCommand> cmdCaptor = ArgumentCaptor.forClass(CertRevocationCommand.class);
        verify(publisher).publishRevocationCommand(cmdCaptor.capture());
        CertRevocationCommand cmd = cmdCaptor.getValue();
        assertThat(cmd.getCertificateXref()).isEqualTo(CERT_XREF);
        assertThat(cmd.getOrganizationId()).isEqualTo(ORGANIZATION_ID.toString());
        assertThat(cmd.getRevocationReason()).isEqualTo("UNSPECIFIED");
        assertThat(cmd.getUserId()).isEqualTo(123);
        assertThat(cmd.getCertSecretHandle()).isNotNull();
        assertThat(cmd.getSerialNumber()).isEqualTo("8A1B2C");
    }

    @Test
    void revoke_idempotent_revoking_returnsWithoutPublish() {
        CertificateEntity c = buildCert("REVOKING");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(c));

        CertificateEntity result = service.revoke(ORGANIZATION_ID, CERT_XREF, new RevokeRequest());

        assertThat(result).isSameAs(c);
        verify(persistenceService, never()).persistRevocation(any(), any(), any(), any(), any(), any());
        verify(publisher, never()).publishRevocationCommand(any());
    }

    @Test
    void revoke_idempotent_revoked_returnsWithoutPublish() {
        CertificateEntity c = buildCert("REVOKED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(c));

        CertificateEntity result = service.revoke(ORGANIZATION_ID, CERT_XREF, new RevokeRequest());

        assertThat(result).isSameAs(c);
        verify(persistenceService, never()).persistRevocation(any(), any(), any(), any(), any(), any());
    }

    @Test
    void revoke_missingCertSecretHandle_throwsBadRequest() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(buildCert("ACTIVE")));

        assertThatThrownBy(() -> service.revoke(ORGANIZATION_ID, CERT_XREF, new RevokeRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("certSecretHandle");
    }

    @Test
    void revoke_retryFromRevocationFailed_persistsRevokingAndPublishesCommand() {
        CertificateEntity failed = buildActiveCertWithKvPath();
        failed.setStatus("REVOCATION_FAILED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(failed));

        CertificateEntity revoking = buildActiveCertWithKvPath();
        revoking.setStatus("REVOKING");
        when(persistenceService.persistRevocation(
                eq(CERT_XREF), eq(ORGANIZATION_ID), eq("REVOCATION_FAILED"), any(), any(), any()))
                .thenReturn(Optional.of(revoking));

        CertificateEntity result = service.revoke(ORGANIZATION_ID, CERT_XREF, new RevokeRequest());

        assertThat(result.getStatus()).isEqualTo("REVOKING");
        verify(persistenceService).persistRevocation(
                eq(CERT_XREF), eq(ORGANIZATION_ID), eq("REVOCATION_FAILED"), any(), any(), any());
        verify(publisher).publishRevocationCommand(any());
    }

    @Test
    void revoke_atomicRaceLost_returnsRevokingIdempotent() {
        CertificateEntity active = buildActiveCertWithKvPath();
        CertificateEntity concurrentRevoking = buildActiveCertWithKvPath();
        concurrentRevoking.setStatus("REVOKING");

        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(active))
                .thenReturn(Optional.of(concurrentRevoking));
        when(persistenceService.persistRevocation(
                eq(CERT_XREF), eq(ORGANIZATION_ID), eq("ACTIVE"), any(), any(), any()))
                .thenReturn(Optional.empty());

        CertificateEntity result = service.revoke(ORGANIZATION_ID, CERT_XREF, new RevokeRequest());

        assertThat(result.getStatus()).isEqualTo("REVOKING");
        verify(publisher, never()).publishRevocationCommand(any());
    }

    @Test
    void revoke_publishFails_marksRevocationFailedAndThrowsServiceUnavailable() {
        CertificateEntity active = buildActiveCertWithKvPath();
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(active));

        CertificateEntity revoking = buildActiveCertWithKvPath();
        revoking.setStatus("REVOKING");
        when(persistenceService.persistRevocation(
                eq(CERT_XREF), eq(ORGANIZATION_ID), eq("ACTIVE"), any(), any(), any()))
                .thenReturn(Optional.of(revoking));
        doThrow(new RuntimeException("publish refused")).when(publisher).publishRevocationCommand(any());

        RevokeRequest req = new RevokeRequest();
        req.setReason("KEY_COMPROMISE");

        assertThatThrownBy(() -> service.revoke(ORGANIZATION_ID, CERT_XREF, req))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("REVOCATION_FAILED");

        verify(persistenceService).markRevocationPublishFailed(
                eq(CERT_XREF), eq(ORGANIZATION_ID), any(), any(), contains("publish refused"));
    }

    // ================================================================== //
    //  Canonical scenario — issuance consistency
    // ================================================================== //

    /**
     * Verifies that for the canonical wildcard+SAN request:
     * - san_domains stored on the cert contains the primary wildcard and all non-redundant patterns
     * - dns_config uses root-domain keys only
     */
    @Test
    void issue_canonicalWildcardSanRequest_storesSanDomainsAndRootDomainDnsConfig() {
        stubDnsCredential("cred-example");
        stubDnsCredential("cred-example");
        UserDomainCertEntity udc = buildUdcForDomain("auto.example.pro");
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "auto.example.pro"))
                .thenReturn(Optional.of(udc));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        service.issue(ORGANIZATION_ID, canonicalIssuanceRequest());

        ArgumentCaptor<CertificateEntity> certCaptor =
                ArgumentCaptor.forClass(CertificateEntity.class);
        ArgumentCaptor<DomainCredentialConfigEntity> credConfigCaptor =
                ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(persistenceService).persistIssuance(
                certCaptor.capture(), credConfigCaptor.capture(), any(), any(), any());

        // san_domains: primary wildcard + 4 non-redundant SANs; no app.* subdomains
        assertThat(certCaptor.getValue().getSanDomains()).containsExactly(
                "*.auto.example.pro",
                "example.pro",
                "*.example.pro",
                "example.tech",
                "*.example.tech");

        // dns_config: root-domain keys only
        assertThat(credConfigCaptor.getValue().getDnsConfig())
                .containsEntry("example.pro", "cred-example")
                .containsEntry("example.tech", "cred-example")
                .hasSize(2);
    }

    /**
     * Verifies that the issuance command sent to the agent has per-group-pruned SAN entries:
     * redundant subdomains covered by a wildcard in the same group are removed.
     */
    @Test
    void issue_canonicalWildcardSanRequest_publishesCommandWithPrunedSanEntries() {
        stubDnsCredential("cred-example");
        stubDnsCredential("cred-example");
        UserDomainCertEntity udc = buildUdcForDomain("auto.example.pro");
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "auto.example.pro"))
                .thenReturn(Optional.of(udc));
        when(persistenceService.persistIssuance(any(), any(), any(), any(), any()))
                .thenReturn(buildCert("PENDING"));

        service.issue(ORGANIZATION_ID, canonicalIssuanceRequest());

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor =
                ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());
        CertIssuanceCommand cmd = cmdCaptor.getValue();

        assertThat(cmd.getDomain()).isEqualTo("auto.example.pro");
        assertThat(cmd.getWildcard()).isTrue();
        assertThat(cmd.getSanDomainEntries()).hasSize(2);

        // Entry 1: app.auto.* and app.example.* removed; wildcard + base kept
        assertThat(cmd.getSanDomainEntries().get(0).getPatterns())
                .containsExactly("*.auto.example.pro", "example.pro", "*.example.pro");

        // Entry 2: app.example.tech removed; base + wildcard kept
        assertThat(cmd.getSanDomainEntries().get(1).getPatterns())
                .containsExactly("example.tech", "*.example.tech");
    }

    /**
     * Verifies that renewal reconstructs the same SAN pattern groups from stored san_domains,
     * including same-root extras (example.pro, *.example.pro) that share the primary credential.
     * This proves renewal produces the identical ACME order as the original issuance.
     */
    @Test
    void renew_canonicalMultiRootSanConfig_reconstructsAllPatternGroupsInCommand() {
        CertificateEntity cert = buildCertWithCanonicalSanDomains("ACTIVE");
        stubCertLookup(cert);

        // Schedule pointing to a config with root-domain keys
        RenewalScheduleEntity schedule = buildSchedule();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));

        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID).userDomainCertId(UDC_ID)
                .dnsConfig(canonicalDnsConfig())
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigService.getById(CONFIG_ID)).thenReturn(credConfig);

        // UDC with the multi-level primary domain
        UserDomainCertEntity udc = buildUdcForDomain("auto.example.pro");
        when(udcRepository.findById(UDC_ID)).thenReturn(Optional.of(udc));

        // Both credentials must be resolved
        stubDnsCredential("cred-example");
        stubDnsCredential("cred-example");
        when(persistenceService.persistRenewal(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new CertPersistenceService.RenewalPersistResult(cert, buildCert("PENDING")));

        service.renew(ORGANIZATION_ID, CERT_XREF, null);

        ArgumentCaptor<CertRenewalCommand> cmdCaptor =
                ArgumentCaptor.forClass(CertRenewalCommand.class);
        verify(publisher).publishRenewal(cmdCaptor.capture());
        CertRenewalCommand cmd = cmdCaptor.getValue();

        assertThat(cmd.getDomain()).isEqualTo("auto.example.pro");
        assertThat(cmd.getWildcard()).isTrue();

        // Two SAN entries reconstructed: example group + example same-root extras
        assertThat(cmd.getSanDomainEntries()).hasSize(2);

        List<List<String>> allPatterns = cmd.getSanDomainEntries().stream()
                .map(CertRenewalCommand.SanDomainEntry::getPatterns)
                .toList();

        assertThat(allPatterns).containsExactlyInAnyOrder(
                List.of("example.tech", "*.example.tech"),
                List.of("example.pro", "*.example.pro"));
    }

    // ================================================================== //
    //  Builders & stubs
    // ================================================================== //

    private UserDomainCertEntity buildUdc() {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();
    }

    private long certIdCounter = 500;

    private CertificateEntity buildCert(String status) {
        UserDomainCertEntity udc = buildUdc();
        return CertificateEntity.builder()
                .id(++certIdCounter)
                .certificateXref(CERT_XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .validTo(OffsetDateTime.now().plusDays(60))
                .san(false)
                .wildcard(false)
                .build();
    }

    private CertificateEntity buildActiveCertWithKvPath() {
        CertificateEntity cert = buildCert("ACTIVE");
        cert.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        return cert;
    }

    private RenewalScheduleEntity buildSchedule() {
        return RenewalScheduleEntity.builder()
                .certificateXref(CERT_XREF)
                .domainCredentialConfigId(CONFIG_ID)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .validTo(OffsetDateTime.now().plusYears(1))
                .renewalEligibleAt(OffsetDateTime.now().plusDays(335))
                .renewalWindowDays(30)
                .enabled(true)
                .build();
    }

        private CredentialReferenceEntity buildCredential(String type, String provider, String secretHandle) {
                return CredentialReferenceEntity.builder()
                                .id(++idCounter)
                                .credentialXref("cred-" + ++idCounter)
                                .organizationId(ORGANIZATION_ID)
                                .type(type)
                                .provider(provider)
                                .secretHandle(secretHandle)
                                .status("ACTIVE")
                                .build();
        }

    private CredentialReferenceEntity buildInactiveCredential(String type, String provider, String secretHandle) {
        return CredentialReferenceEntity.builder()
                .id(++certIdCounter)
                .credentialXref("cred-" + ++certIdCounter)
                .organizationId(ORGANIZATION_ID)
                .type(type)
                .provider(provider)
                .secretHandle(secretHandle)
                .status("INACTIVE")
                .build();
    }

    private void stubDnsCredential(String xref) {
        when(credentialService.getByXref(ORGANIZATION_ID, xref))
                .thenReturn(buildCredential("DNS", "AZURE_DNS", "https://kv.vault.azure.net/secrets/dns-cred"));
    }

    private void stubOptionalCredential(String xref, String type, String provider) {
        when(credentialService.getByXref(ORGANIZATION_ID, xref))
                .thenReturn(buildCredential(type, provider, "https://kv.vault.azure.net/secrets/" + xref));
    }

    private void stubDeployCredential(String xref, String provider) {
        when(credentialService.getByXref(ORGANIZATION_ID, xref))
                .thenReturn(buildCredential("DEPLOYMENT", provider,
                        "https://kv.vault.azure.net/secrets/deploy-cred"));
    }

    private void stubUdcLookup() {
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, "example.com"))
                .thenReturn(Optional.of(buildUdc()));
    }

    private void stubUdcById() {
        when(udcRepository.findById(UDC_ID))
                .thenReturn(Optional.of(buildUdc()));
    }

    private void stubCertLookup(CertificateEntity cert) {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(CERT_XREF, ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
    }

    private void stubScheduleAndCredConfig() {
        RenewalScheduleEntity schedule = buildSchedule();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));

        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .userDomainCertId(UDC_ID)
                .dnsConfig(Map.of("example.com", DNS_XREF))
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigService.getById(CONFIG_ID)).thenReturn(credConfig);
    }

    private CertIssuanceRequest issuanceRequest() {
        CertIssuanceRequest r = new CertIssuanceRequest();
        r.setDomain("example.com");
        r.setWildcard(false);
        r.setSan(false);
        r.setCaProvider(CaProvider.LETS_ENCRYPT);
        r.setDnsCredentialXref(DNS_XREF);
        return r;
    }

    private CertDeployRequest deployRequest() {
        CertDeployRequest r = new CertDeployRequest();
        r.setDeploymentCredentialXref(DEPLOY_XREF);
        r.setTargetType(TargetType.AZURE_KV);
        return r;
    }

    // ------------------------------------------------------------------ //
    //  Canonical scenario helpers
    // ------------------------------------------------------------------ //

    private UserDomainCertEntity buildUdcForDomain(String domain) {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(ORGANIZATION_ID)
                .domain(domain)
                .build();
    }

    private CertificateEntity buildCertWithCanonicalSanDomains(String status) {
        UserDomainCertEntity udc = buildUdcForDomain("auto.example.pro");
        return CertificateEntity.builder()
                .id(++certIdCounter)
                .certificateXref(CERT_XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .wildcard(true)
                .san(true)
                .sanDomains(new String[]{
                        "*.auto.example.pro",
                        "example.pro",
                        "*.example.pro",
                        "example.tech",
                        "*.example.tech"})
                .build();
    }

    private Map<String, String> canonicalDnsConfig() {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("example.pro", "cred-example");
        config.put("example.tech", "cred-example");
        return config;
    }

    private CertIssuanceRequest canonicalIssuanceRequest() {
        CertIssuanceRequest r = new CertIssuanceRequest();
        r.setDomain("auto.example.pro");
        r.setWildcard(true);
        r.setSan(true);
        r.setCaProvider(CaProvider.LETS_ENCRYPT);
        r.setDnsCredentialXref("cred-example");

        CertIssuanceRequest.SanDomainEntry entry1 = new CertIssuanceRequest.SanDomainEntry();
        entry1.setPatterns(List.of("app.auto.example.pro", "*.auto.example.pro",
                                   "app.example.pro", "example.pro", "*.example.pro"));
        entry1.setDnsCredentialXref("cred-example");

        CertIssuanceRequest.SanDomainEntry entry2 = new CertIssuanceRequest.SanDomainEntry();
        entry2.setPatterns(List.of("example.tech", "app.example.tech", "*.example.tech"));
        entry2.setDnsCredentialXref("cred-example");

        r.setSanDomainEntries(List.of(entry1, entry2));
        return r;
    }

    @Test
    void resolveCredentialRefsForResponseBatch_pageOf50_issuesExactlyTwoQueries() {
        java.util.List<CertificateEntity> certs = new java.util.ArrayList<>();
        for (int i = 0; i < 50; i++) {
            CertificateEntity c = new CertificateEntity();
            c.setCertificateXref("cert-" + i);
            c.setUserDomainCertId((long) (100 + i));
            certs.add(c);
        }

        java.util.List<DomainCredentialConfigEntity> configs = new java.util.ArrayList<>();
        for (int i = 0; i < 50; i++) {
            DomainCredentialConfigEntity cfg = new DomainCredentialConfigEntity();
            cfg.setUserDomainCertId((long) (100 + i));
            cfg.setDnsConfig(java.util.Map.of("root", DNS_XREF));
            cfg.setDeploymentTargets(java.util.List.of(DEPLOY_XREF));
            configs.add(cfg);
        }
        when(domainCredConfigRepository.findByUserDomainCertIdIn(any())).thenReturn(configs);

        CredentialReferenceEntity dnsCred = new CredentialReferenceEntity();
        dnsCred.setCredentialXref(DNS_XREF);
        dnsCred.setSecretHandle("kv://dns");
        CredentialReferenceEntity deployCred = new CredentialReferenceEntity();
        deployCred.setCredentialXref(DEPLOY_XREF);
        deployCred.setSecretHandle("kv://deploy");
        when(credentialService.getByXrefsInternal(any()))
                .thenReturn(java.util.Map.of(DNS_XREF, dnsCred, DEPLOY_XREF, deployCred));

        var result = service.resolveCredentialRefsForResponseBatch(certs);

        assertThat(result).hasSize(50);
        verify(domainCredConfigRepository, org.mockito.Mockito.times(1)).findByUserDomainCertIdIn(any());
        verify(credentialService, org.mockito.Mockito.times(1)).getByXrefsInternal(any());
        verify(domainCredConfigRepository, org.mockito.Mockito.never()).findByUserDomainCertId(any());
        verify(credentialService, org.mockito.Mockito.never()).getByXrefInternal(any());

        CertIssuanceService.CredentialRefs r0 = result.get("cert-0");
        assertThat(r0.dnsCredentialKvPath()).isEqualTo("kv://dns");
        assertThat(r0.deploymentCredentialKvPaths()).containsExactly("kv://deploy");
    }

    @Test
    void resolveCredentialRefsForResponseBatch_emptyPage_shortCircuits() {
        var result = service.resolveCredentialRefsForResponseBatch(java.util.List.of());
        assertThat(result).isEmpty();
        verify(domainCredConfigRepository, org.mockito.Mockito.never()).findByUserDomainCertIdIn(any());
        verify(credentialService, org.mockito.Mockito.never()).getByXrefsInternal(any());
    }

    @Test
    void resolveCredentialRefsForResponseBatch_certsWithNoUdcId_returnEmptyRefs() {
        CertificateEntity c = new CertificateEntity();
        c.setCertificateXref("cert-no-udc");
        var result = service.resolveCredentialRefsForResponseBatch(java.util.List.of(c));

        assertThat(result.get("cert-no-udc").dnsConfigXref()).isEmpty();
        verify(domainCredConfigRepository, org.mockito.Mockito.never()).findByUserDomainCertIdIn(any());
    }
}
