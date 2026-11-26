// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.credconfig.AddDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.EditDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.KubernetesDeploymentConfigRequest;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DomainCredentialConfigServiceTest {

    @Mock private DomainCredentialConfigRepository configRepository;
    @Mock private UserDomainCertRepository          udcRepository;
    @Mock private CredentialReferenceService         credentialService;
    @Mock private CertDeploymentConfigService certDeploymentConfigService;
    @Mock private RenewalScheduleRepository renewalScheduleRepository;
    @Mock private com.certmanagement.repository.CredentialReferenceRepository credentialRepository;
    @Mock private com.certmanagement.service.audit.CredentialAuditRecorder credentialAudit;

    private DomainCredentialConfigService service;
    private long idCounter = 100;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private static final Long   ORGANIZATION_ID  = 1L;
    private static final Long   UDC_ID     = 2L;
    private static final Long   CONFIG_ID  = 3L;
    private static final String DOMAIN     = "example.com";
    private static final String DNS_XREF   = "cred-dns-1";
    private static final String DEPLOY_XREF = "cred-deploy-1";

    @BeforeEach
    void setUp() {
        service = new DomainCredentialConfigService(
                configRepository, udcRepository, credentialService, certDeploymentConfigService,
                renewalScheduleRepository, org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureLifecycleLock.class),
                credentialRepository, credentialAudit);
    }

    // ================================================================== //
    //  getForOrganization()
    // ================================================================== //

    @Test
    void getForOrganization_happyPath_returnsConfig() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));

        DomainCredentialConfigEntity result = service.getForOrganization(ORGANIZATION_ID, DOMAIN);

        assertThat(result.getId()).isEqualTo(CONFIG_ID);
    }

    @Test
    void getForOrganization_noUdc_throwsResourceNotFound() {
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, DOMAIN)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getForOrganization(ORGANIZATION_ID, DOMAIN))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("domain registration");
    }

    @Test
    void getForOrganization_noConfig_throwsResourceNotFound() {
        stubUdcLookup();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getForOrganization(ORGANIZATION_ID, DOMAIN))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("credential config");
    }

    // ================================================================== //
    //  patchDnsCredential()
    // ================================================================== //

    @Test
    void patchDnsCredential_happyPath_updatesDnsConfigEntry() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DNS_XREF))
                .thenReturn(buildCredential("DNS", "AZURE_DNS"));
        when(configRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        DomainCredentialConfigEntity result = service.patchDnsCredential(ORGANIZATION_ID, DOMAIN, DOMAIN, DNS_XREF);

        assertThat(result.getDnsConfig()).containsEntry(DOMAIN, DNS_XREF);
        verify(configRepository).save(config);
        verify(renewalScheduleRepository).rearmParkedFailuresByDomainCredentialConfigId(CONFIG_ID);
    }

    @Test
    void patchDnsCredential_wrongCredentialType_throwsBadRequest() {
        when(credentialService.getByXref(ORGANIZATION_ID, DNS_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV")); // wrong type

        assertThatThrownBy(() -> service.patchDnsCredential(ORGANIZATION_ID, DOMAIN, DOMAIN, DNS_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be type DNS");
    }

    @Test
    void patchDnsCredential_inactiveCredential_throwsBadRequest() {
        CredentialReferenceEntity inactive = buildCredential("DNS", "AZURE_DNS");
        inactive.setStatus("INACTIVE");
        when(credentialService.getByXref(ORGANIZATION_ID, DNS_XREF)).thenReturn(inactive);

        assertThatThrownBy(() -> service.patchDnsCredential(ORGANIZATION_ID, DOMAIN, DOMAIN, DNS_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not ACTIVE");
    }

    // ================================================================== //
    //  addDeploymentTarget()
    // ================================================================== //

    @Test
    void addDeploymentTarget_happyPath_appendsToList() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig(); // deploymentTargets is empty
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));
        when(configRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        DomainCredentialConfigEntity result = service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, addTargetRequest(DEPLOY_XREF));

        assertThat(result.getDeploymentTargets()).contains(DEPLOY_XREF);
        verify(configRepository).save(config);
    }

    @Test
    void addDeploymentTarget_alreadyPresent_idempotentNoSave() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of(DEPLOY_XREF))); // already there
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));

        service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, addTargetRequest(DEPLOY_XREF));

        verify(configRepository, never()).save(any());
    }

    @Test
    void addDeploymentTarget_wrongType_throwsBadRequest() {
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DNS", "AZURE_DNS")); // wrong type

        assertThatThrownBy(() -> service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, addTargetRequest(DEPLOY_XREF)))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be type DEPLOYMENT");
    }

    @Test
    void addDeploymentTarget_kubernetesConfig_upsertsConfig() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "KUBERNETES_SECRETS"));
        when(configRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        AddDeploymentTargetRequest request = addTargetRequest(DEPLOY_XREF);
        KubernetesDeploymentConfigRequest k8sConfig = new KubernetesDeploymentConfigRequest();
        k8sConfig.setNsSecretMap(objectMapper.readTree("[{\"dev\":\"example-dev-tls\"}]"));
        request.setConfig(k8sConfig);

        service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, request);

        verify(certDeploymentConfigService).validateAndUpsertKubernetesConfig(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), any());
    }

    @Test
    void addDeploymentTarget_kubernetesUseDefault_ignoresProvidedNsSecretMap() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "KUBERNETES_SECRETS"));
        when(configRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        AddDeploymentTargetRequest request = addTargetRequest(DEPLOY_XREF);
        KubernetesDeploymentConfigRequest k8sConfig = new KubernetesDeploymentConfigRequest();
        k8sConfig.setUseDefault(true);
        k8sConfig.setNsSecretMap(objectMapper.readTree("[{\"dev\":\"ignored-secret\"}]"));
        request.setConfig(k8sConfig);

        service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, request);

        verify(certDeploymentConfigService).requireReconciledConfigJson(
                eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class));
        verify(certDeploymentConfigService, never()).validateAndUpsertKubernetesConfig(anyLong(), anyLong(), any(), any());
    }

        @Test
        void addDeploymentTarget_withTargets_callsUpsertGenericTargets() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));
        when(configRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        AddDeploymentTargetRequest request = addTargetRequest(DEPLOY_XREF);
        request.setTargets(objectMapper.readTree("{\"vaults\":[{\"vaultUri\":\"https://kv.vault.azure.net\",\"certificateName\":\"example-com\"}]}"));

        service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, request);

        verify(certDeploymentConfigService).upsertGenericTargets(
            eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), any());
        }

        @Test
        void addDeploymentTarget_withConfigAndTargets_throwsBadRequest() throws Exception {
            when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
                .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));
        AddDeploymentTargetRequest request = addTargetRequest(DEPLOY_XREF);
        KubernetesDeploymentConfigRequest k8sConfig = new KubernetesDeploymentConfigRequest();
        k8sConfig.setNsSecretMap(objectMapper.readTree("[{\"dev\":\"example-dev\"}]"));
        request.setConfig(k8sConfig);
        request.setTargets(objectMapper.readTree("{\"vaults\":[]}"));

        assertThatThrownBy(() -> service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, request))
            .isInstanceOf(BadRequestException.class)
            .hasMessageContaining("Provide either 'config'");
        }

        @Test
        void addDeploymentTarget_targetsForK8s_throwsBadRequest() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "KUBERNETES_SECRETS"));

        AddDeploymentTargetRequest request = addTargetRequest(DEPLOY_XREF);
        request.setTargets(objectMapper.readTree("{\"any\":\"thing\"}"));

        assertThatThrownBy(() -> service.addDeploymentTarget(ORGANIZATION_ID, DOMAIN, request))
            .isInstanceOf(BadRequestException.class)
            .hasMessageContaining("Use the legacy 'config' field");
        }

        // ================================================================== //
        //  editDeploymentTarget()
        // ================================================================== //

        @Test
        void editDeploymentTarget_nonTarget_throwsBadRequest() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of("cred-deploy-2")));
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));

        EditDeploymentTargetRequest request = new EditDeploymentTargetRequest();
        request.setTargets(objectMapper.readTree("{\"vaults\":[]}"));

        assertThatThrownBy(() -> service.editDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF, request))
            .isInstanceOf(BadRequestException.class)
            .hasMessageContaining("is not a deployment target");
        }

        @Test
        void editDeploymentTarget_k8sRequiresNsSecretMap() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of(DEPLOY_XREF)));
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "KUBERNETES_SECRETS"));

        EditDeploymentTargetRequest request = new EditDeploymentTargetRequest();
        KubernetesDeploymentConfigRequest k8sConfig = new KubernetesDeploymentConfigRequest();
        k8sConfig.setUseDefault(true);
        request.setConfig(k8sConfig);

        assertThatThrownBy(() -> service.editDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF, request))
            .isInstanceOf(BadRequestException.class)
            .hasMessageContaining("useDefault is invalid for edit");
        }

        @Test
        void editDeploymentTarget_k8sWithNsSecretMap_callsValidator() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of(DEPLOY_XREF)));
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "KUBERNETES_SECRETS"));

        EditDeploymentTargetRequest request = new EditDeploymentTargetRequest();
        KubernetesDeploymentConfigRequest k8sConfig = new KubernetesDeploymentConfigRequest();
        k8sConfig.setNsSecretMap(objectMapper.readTree("[{\"dev\":\"example-dev\"}]"));
        request.setConfig(k8sConfig);

        service.editDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF, request);

        verify(certDeploymentConfigService).validateAndUpsertKubernetesConfig(
            eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), any());
        }

        @Test
        void editDeploymentTarget_nonK8sRequiresTargets() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of(DEPLOY_XREF)));
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));

        EditDeploymentTargetRequest request = new EditDeploymentTargetRequest();

        assertThatThrownBy(() -> service.editDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF, request))
            .isInstanceOf(BadRequestException.class)
            .hasMessageContaining("targets is required");
        }

        @Test
        void editDeploymentTarget_nonK8s_callsUpsertGenericTargets() throws Exception {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of(DEPLOY_XREF)));
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(credentialService.getByXref(ORGANIZATION_ID, DEPLOY_XREF))
            .thenReturn(buildCredential("DEPLOYMENT", "AZURE_KV"));

        EditDeploymentTargetRequest request = new EditDeploymentTargetRequest();
        request.setTargets(objectMapper.readTree("{\"vaults\":[{\"vaultUri\":\"https://kv.vault.azure.net\",\"certificateName\":\"example-com\"}]}"));

        service.editDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF, request);

        verify(certDeploymentConfigService).upsertGenericTargets(
            eq(ORGANIZATION_ID), eq(UDC_ID), any(CredentialReferenceEntity.class), any());
        }

    // ================================================================== //
    //  removeDeploymentTarget()
    // ================================================================== //

    @Test
    void removeDeploymentTarget_happyPath_removesFromList() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig();
        config.setDeploymentTargets(new ArrayList<>(List.of(DEPLOY_XREF, "cred-deploy-2")));
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));
        when(configRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        DomainCredentialConfigEntity result = service.removeDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF);

        assertThat(result.getDeploymentTargets()).doesNotContain(DEPLOY_XREF);
        assertThat(result.getDeploymentTargets()).contains("cred-deploy-2");
        verify(configRepository).save(config);
    }

    @Test
    void removeDeploymentTarget_notPresent_idempotentNoSave() {
        stubUdcLookup();
        DomainCredentialConfigEntity config = buildConfig(); // empty list
        when(configRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(config));

        service.removeDeploymentTarget(ORGANIZATION_ID, DOMAIN, DEPLOY_XREF);

        verify(configRepository, never()).save(any());
    }

    // ================================================================== //
    //  Builders & stubs
    // ================================================================== //

    private UserDomainCertEntity buildUdc() {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(ORGANIZATION_ID)
                .domain(DOMAIN)
                .build();
    }

    private DomainCredentialConfigEntity buildConfig() {
        return DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .userDomainCertId(UDC_ID)
                .dnsConfig(new LinkedHashMap<>(Map.of(DOMAIN, "cred-dns-old")))
                .deploymentTargets(new ArrayList<>())
                .build();
    }

    private CredentialReferenceEntity buildCredential(String type, String provider) {
        return CredentialReferenceEntity.builder()
                .id(++idCounter)
                .credentialXref(String.valueOf(++idCounter))
                .organizationId(ORGANIZATION_ID)
                .type(type)
                .provider(provider)
                .secretHandle("https://kv.vault.azure.net/secrets/cred")
                .status("ACTIVE")
                .build();
    }

    private AddDeploymentTargetRequest addTargetRequest(String credentialXref) {
        AddDeploymentTargetRequest request = new AddDeploymentTargetRequest();
        request.setCredentialXref(credentialXref);
        return request;
    }

    private void stubUdcLookup() {
        when(udcRepository.findByOrganizationIdAndDomain(ORGANIZATION_ID, DOMAIN))
                .thenReturn(Optional.of(buildUdc()));
    }
}
