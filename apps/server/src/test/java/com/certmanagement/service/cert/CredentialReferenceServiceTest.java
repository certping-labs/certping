// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.CredentialRejectedException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.deployment.config.DeploymentScopeValidatorRegistry;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialReferenceServiceTest {

    @Mock
    private CredentialReferenceRepository credentialRepo;

    @Mock
    private DomainCredentialConfigRepository domainCredentialConfigRepo;

    @Mock
    private CertDeploymentConfigRepository certDeploymentConfigRepo;

    @Mock
    private OrganizationRepository organizationRepository;

    @Mock
    private KubernetesDeploymentConfigValidator kubernetesConfigValidator;

    @Mock
    private DeploymentScopeValidatorRegistry scopeValidatorRegistry;

    @Spy
    private ObjectMapper objectMapper = new tools.jackson.databind.json.JsonMapper();

    @Spy
    private CredJsonDispatcher credJsonDispatcher =
            new CredJsonDispatcher(JsonMapper.builderWithJackson2Defaults().findAndAddModules().build());


    @Mock
    private AgentSecretWriter agentSecretWriter;

    @Mock
    private RenewalScheduleRepository renewalScheduleRepository;

    @Mock private com.certmanagement.service.lifecycle.FeatureLifecycleLock featureLifecycleLock;

    @Mock private com.certmanagement.service.audit.CredentialAuditRecorder credentialAudit;

    @InjectMocks
    private CredentialReferenceService credentialReferenceService;

    private static final String CERTPING_KEY_DETAILS =
            "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}";

    @Test
    void list_withoutType_usesUpdatedAtOrderedRepositoryMethod() {
        Long organizationId = 1L;
        when(credentialRepo.findByOrganizationIdAndStatusOrderByUpdatedAtDesc(organizationId, "ACTIVE"))
                .thenReturn(List.of(CredentialReferenceEntity.builder().credentialXref("cred-1").build()));

        List<CredentialReferenceEntity> result = credentialReferenceService.list(organizationId, null);

        assertThat(result).hasSize(1);
        verify(credentialRepo).findByOrganizationIdAndStatusOrderByUpdatedAtDesc(organizationId, "ACTIVE");
    }

    @Test
    void list_withType_usesUpdatedAtOrderedRepositoryMethod() {
        Long organizationId = 1L;
        when(credentialRepo.findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(organizationId, "DNS", "ACTIVE"))
                .thenReturn(List.of(CredentialReferenceEntity.builder().credentialXref("cred-2").type("DNS").build()));

        List<CredentialReferenceEntity> result = credentialReferenceService.list(organizationId, "dns");

        assertThat(result).hasSize(1);
        verify(credentialRepo).findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(organizationId, "DNS", "ACTIVE");
    }

    @Test
    void registerDeployment_validatesKubernetesConfigForKubernetesProvider() {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        credentialReferenceService.registerDeployment(
                1L,
                "KUBERNETES_SECRETS",
                "k8s deploy cred",
                "https://kv.vault.azure.net/secrets/k8s-cred",
                "{\"authMethod\":\"AWS\",\"clusterName\":\"prod\",\"namespaces\":\"all_namespaces\"}",
                null);

        verify(kubernetesConfigValidator).validateForProvider(
                "KUBERNETES_SECRETS",
                "{\"authMethod\":\"AWS\",\"clusterName\":\"prod\",\"namespaces\":\"all_namespaces\"}");
    }

    @Test
    void registerDeployment_allowsNullKvPathForKubernetesSaIncluster() {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerDeployment(
                1L,
                "KUBERNETES_SECRETS",
                "k8s incluster cred",
                null,
                "{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"prod\",\"namespaces\":[\"dev\"]}",
                null);

        assertThat(saved.getSecretHandle()).isNull();
    }

    @Test
    void registerDeployment_rejectsNullKvPathForNonInclusterProviders() {
        when(organizationRepository.existsById(1L)).thenReturn(true);

        assertThatThrownBy(() -> credentialReferenceService.registerDeployment(
                1L,
                "AWS_ACM",
                "aws deploy cred",
                null,
                null,
                null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("secretHandle is required");
    }

    @Test
    void registerDeployment_allowsNullKvPathForAwsInstanceProfile() {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerDeployment(
                1L,
                "AWS_ACM",
                "aws acm instance profile",
                null,
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}",
                null);

        assertThat(saved.getSecretHandle()).isNull();
        assertThat(saved.getProvider()).isEqualTo("AWS_ACM");
    }

    @Test
    void registerDeployment_rejectsNullKvPathForAwsNonInstanceProfile() {
        when(organizationRepository.existsById(1L)).thenReturn(true);

        assertThatThrownBy(() -> credentialReferenceService.registerDeployment(
                1L,
                "AWS_ACM",
                "aws deploy cred",
                null,
                "{\"authMode\":\"STATIC_KEYS\",\"region\":\"us-east-1\"}",
                null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("secretHandle is required");
    }

    @Test
    void registerDeployment_allowsNullKvPathForAzureWorkloadIdentity() {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerDeployment(
                1L,
                "AZURE_KV",
                "azure kv workload identity",
                null,
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"tenantId\":\"tid-1\",\"subscriptionId\":\"sid-1\"}",
                null);

        assertThat(saved.getSecretHandle()).isNull();
        assertThat(saved.getProvider()).isEqualTo("AZURE_KV");
    }

    @Test
    void registerDeployment_rejectsNullKvPathForAzureServicePrincipal() {
        when(organizationRepository.existsById(1L)).thenReturn(true);

        assertThatThrownBy(() -> credentialReferenceService.registerDeployment(
                1L,
                "AZURE_KV",
                "azure kv sp cred",
                null,
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"tid-1\"}",
                null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("secretHandle is required");
    }

    @Test
    void registerDeployment_rejectsDomainCertificateMapsOnCredential() {
        when(organizationRepository.existsById(1L)).thenReturn(true);

        assertThatThrownBy(() -> credentialReferenceService.registerDeployment(
                1L,
                "AWS_ACM",
                "aws deploy cred",
                "https://kv.vault.azure.net/secrets/deploy",
                "{\"domainCertificateArns\":{\"example.com\":\"arn:aws:acm:...\"}}",
                null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("domainCertificateArns");
    }

    @Test
    void updateCredential_validatesUsingExistingProviderAndPersistsConfig() {
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-k8s-1")
                .organizationId(1L)
                .provider("KUBERNETES_SECRETS")
                .type("DEPLOYMENT")
                .status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/old")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-k8s-1", 1L))
                .thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);

        String newConfig = "{\"authMethod\":\"AZURE\",\"clusterName\":\"prod\",\"namespaces\":[\"dev\",\"prod\"]}";
        CredentialReferenceEntity saved = credentialReferenceService.updateCredential(
                1L,
                "cred-k8s-1",
                "https://kv.vault.azure.net/secrets/new",
                newConfig,
                null);

        assertThat(saved.getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/new");
        assertThat(saved.getConfigJson()).isEqualTo(newConfig);
        verify(kubernetesConfigValidator).validateForProvider("KUBERNETES_SECRETS", newConfig);
        verify(credentialRepo).save(existing);
    }

    @Test
    void updateCredential_allowsNullKvPathForKubernetesSaIncluster() {
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-k8s-2")
                .organizationId(1L)
                .provider("KUBERNETES_SECRETS")
                .type("DEPLOYMENT")
                .status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/old")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-k8s-2", 1L))
                .thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);

        String config = "{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"prod\",\"namespaces\":[\"dev\"]}";
        CredentialReferenceEntity saved = credentialReferenceService.updateCredential(1L, "cred-k8s-2", null, config, null);

        assertThat(saved.getSecretHandle()).isNull();
        verify(credentialRepo).save(existing);
    }

    // ───────────────────────────── credJson flows ─────────────────────────────────

    @Test
    void registerDns_withCredJson_materializesToAgentKvAndPersistsReturnedPath() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(org.mockito.ArgumentMatchers.eq(1L), anyString()))
                .thenReturn("certping-org1-cred-xyz");
        when(agentSecretWriter.writeSecret(org.mockito.ArgumentMatchers.eq("certping-org1-cred-xyz"), anyString()))
                .thenReturn("https://example-vault.vault.azure.net/secrets/certping-org1-cred-xyz");
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree("{\"apiToken\":\"cf-token\"}");
        CredentialReferenceEntity saved = credentialReferenceService.registerDns(
                1L, "CLOUDFLARE", "primary cloudflare dns", null, credJson, null);

        assertThat(saved.getSecretHandle())
                .isEqualTo("https://example-vault.vault.azure.net/secrets/certping-org1-cred-xyz");
        // Cloudflare DNS payload is now JSON for consistency with all other DNS providers.
        org.mockito.ArgumentCaptor<String> valueCap = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(agentSecretWriter).writeSecret(org.mockito.ArgumentMatchers.eq("certping-org1-cred-xyz"), valueCap.capture());
        assertThat(objectMapper.readTree(valueCap.getValue()))
                .isEqualTo(objectMapper.readTree("{\"apiToken\":\"cf-token\"}"));
    }

    @Test
    void registerCa_digiCertKey_isStoredForTheAgentAsACaCredential() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(org.mockito.ArgumentMatchers.eq(1L), anyString())).thenReturn("certping-org1-ca");
        when(agentSecretWriter.writeSecret(org.mockito.ArgumentMatchers.eq("certping-org1-ca"), anyString()))
                .thenReturn("https://example-vault.vault.azure.net/secrets/certping-org1-ca");
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerCa(
                1L, " digicert ", "CertCentral", null, objectMapper.readTree("{\"apiKey\":\"dc-key\",\"extra\":1}"));

        assertThat(saved.getType()).isEqualTo("CA");
        assertThat(saved.getProvider()).isEqualTo("DIGICERT");
        assertThat(saved.getStatus()).isEqualTo("ACTIVE");
        assertThat(saved.getSecretHandle()).isEqualTo("https://example-vault.vault.azure.net/secrets/certping-org1-ca");
        org.mockito.ArgumentCaptor<String> value = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(agentSecretWriter).writeSecret(org.mockito.ArgumentMatchers.eq("certping-org1-ca"), value.capture());
        assertThat(objectMapper.readTree(value.getValue())).isEqualTo(objectMapper.readTree("{\"apiKey\":\"dc-key\"}"));
        verify(featureLifecycleLock).lockAndAssertEnabled(1L, com.certmanagement.constants.FeatureFlags.CREDENTIALS_MANAGEMENT);
    }

    @Test
    void registerCa_ownKeyVaultSecret_keepsThePath() {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerCa(
                1L, "DIGICERT", "own vault", "https://customer.vault.azure.net/secrets/digicert-key", null);

        assertThat(saved.getSecretHandle()).isEqualTo("https://customer.vault.azure.net/secrets/digicert-key");
        verify(agentSecretWriter, org.mockito.Mockito.never()).writeSecret(anyString(), anyString());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"GLOBALSIGN", "LETS_ENCRYPT", "CLOUDFLARE", ""})
    void registerCa_aCaThatTakesNoCustomerKey_isRefused(String provider) {
        when(organizationRepository.existsById(1L)).thenReturn(true);

        assertThatThrownBy(() -> credentialReferenceService.registerCa(
                1L, provider, "d", null, objectMapper.createObjectNode().put("apiKey", "k")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Only DigiCert");
        verify(credentialRepo, org.mockito.Mockito.never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void registerCa_blankDigiCertKey_isRefused() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(organizationRepository.existsById(1L)).thenReturn(true);

        assertThatThrownBy(() -> credentialReferenceService.registerCa(
                1L, "DIGICERT", "d", null, objectMapper.readTree("{\"apiKey\":\"  \"}")))
                .isInstanceOf(CredentialRejectedException.class)
                .hasMessageContaining("DigiCert API key is required");
    }

    // ───────────────────────────── CA credential management ─────────────────────

    private CredentialReferenceEntity digiCertCredential(long organizationId) {
        return CredentialReferenceEntity.builder()
                .credentialXref("cred-ca").organizationId(organizationId).provider("DIGICERT").type("CA")
                .status("ACTIVE").secretHandle("https://example-vault.vault.azure.net/secrets/certping-org1-ca")
                .build();
    }

    @Test
    void replaceCaKey_overwritesTheKeyInPlace_keepingTheXrefAndHandle() throws Exception {
        CredentialReferenceEntity existing = digiCertCredential(1L);
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-ca", 1L)).thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);
        when(agentSecretWriter.isAvailable()).thenReturn(true);

        CredentialReferenceEntity saved = credentialReferenceService.replaceCaKey(
                1L, "cred-ca", null, objectMapper.readTree("{\"apiKey\":\"new-key\"}"));

        assertThat(saved.getCredentialXref()).isEqualTo("cred-ca");
        assertThat(saved.getSecretHandle()).isEqualTo(existing.getSecretHandle());
        org.mockito.ArgumentCaptor<String> value = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(agentSecretWriter).overwriteAtHandle(org.mockito.ArgumentMatchers.eq(existing.getSecretHandle()),
                value.capture());
        assertThat(objectMapper.readTree(value.getValue())).isEqualTo(objectMapper.readTree("{\"apiKey\":\"new-key\"}"));
    }

    @Test
    void replaceCaKey_anotherOrganizationsCredential_isNotFound() {
        assertThatThrownBy(() -> credentialReferenceService.replaceCaKey(
                2L, "cred-ca", null, objectMapper.createObjectNode().put("apiKey", "k")))
                .isInstanceOf(com.certmanagement.exception.ResourceNotFoundException.class);
        verify(agentSecretWriter, org.mockito.Mockito.never()).overwriteAtHandle(anyString(), anyString());
    }

    @Test
    void replaceCaKey_aDnsCredential_isNotFound() {
        CredentialReferenceEntity dns = digiCertCredential(1L);
        dns.setType("DNS");
        dns.setProvider("CLOUDFLARE");
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-ca", 1L)).thenReturn(Optional.of(dns));

        assertThatThrownBy(() -> credentialReferenceService.replaceCaKey(
                1L, "cred-ca", null, objectMapper.createObjectNode().put("apiKey", "k")))
                .isInstanceOf(com.certmanagement.exception.ResourceNotFoundException.class);
    }

    @Test
    void replaceCaKey_withoutAKey_isRefused() {
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-ca", 1L))
                .thenReturn(Optional.of(digiCertCredential(1L)));

        assertThatThrownBy(() -> credentialReferenceService.replaceCaKey(1L, "cred-ca", " ", null))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void deleteCa_anotherOrganizationsCredential_isNotFound_andNothingChanges() {
        // The credential exists for organization 1; organization 2 asks to delete it.
        org.mockito.Mockito.lenient().when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-ca", 1L))
                .thenReturn(Optional.of(digiCertCredential(1L)));

        assertThatThrownBy(() -> credentialReferenceService.deleteCa(2L, "cred-ca"))
                .isInstanceOf(com.certmanagement.exception.ResourceNotFoundException.class);
        verify(credentialRepo, never()).save(any());
        verify(credentialRepo, never()).countActiveCertsReferencingCredential(anyString());
    }

    @Test
    void listCa_asksOnlyForTheCallersOrganization() {
        when(credentialRepo.findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(2L, "CA", "ACTIVE"))
                .thenReturn(List.of());

        assertThat(credentialReferenceService.listCa(2L)).isEmpty();

        verify(credentialRepo).findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(2L, "CA", "ACTIVE");
        verify(credentialRepo, never()).findByCredentialXref(anyString());
    }

    @Test
    void deleteCa_stillUsedByACertificate_isRefusedAsInUse() {
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-ca", 1L))
                .thenReturn(Optional.of(digiCertCredential(1L)));
        when(credentialRepo.countActiveCertsReferencingCredential("cred-ca")).thenReturn(2L);

        assertThatThrownBy(() -> credentialReferenceService.deleteCa(1L, "cred-ca"))
                .isInstanceOf(CredentialRejectedException.class)
                .satisfies(e -> assertThat(((CredentialRejectedException) e).getCode())
                        .isEqualTo(CredentialRejectedException.IN_USE));
        verify(credentialRepo, org.mockito.Mockito.never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void deleteCa_unused_softDeletes() {
        CredentialReferenceEntity existing = digiCertCredential(1L);
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-ca", 1L)).thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);

        assertThat(credentialReferenceService.deleteCa(1L, "cred-ca").getStatus()).isEqualTo("DELETED");
    }

    @Test
    void listCa_listsOnlyActiveCaCredentials() {
        when(credentialRepo.findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(1L, "CA", "ACTIVE"))
                .thenReturn(List.of(digiCertCredential(1L)));
        assertThat(credentialReferenceService.listCa(1L)).extracting(CredentialReferenceEntity::getCredentialXref)
                .containsExactly("cred-ca");
    }

    @Test
    void registerDns_withBothKvPathAndCredJson_rejects() throws Exception {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        tools.jackson.databind.JsonNode credJson = objectMapper.readTree("{\"apiToken\":\"x\"}");

        assertThatThrownBy(() -> credentialReferenceService.registerDns(
                1L, "CLOUDFLARE", "d", "https://kv.vault.azure.net/secrets/foo", credJson, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("either secretHandle or credJson");
    }

    @Test
    void registerDns_namecheapAllowsKvPathWithNonSecretCredJson() throws Exception {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"apiUser\":\"nc-user\",\"username\":\"nc-user\",\"apiKey\":\"must-not-store\"}");
        CredentialReferenceEntity saved = credentialReferenceService.registerDns(
                1L,
                "NAMECHEAP",
                "namecheap dns",
                "https://kv.vault.azure.net/secrets/namecheap-api-key",
                credJson, null);

        assertThat(saved.getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/namecheap-api-key");
        assertThat(objectMapper.readTree(saved.getConfigJson()))
                .isEqualTo(objectMapper.readTree("{\"apiUser\":\"nc-user\",\"username\":\"nc-user\"}"));
        assertThat(saved.getConfigJson()).doesNotContain("apiKey");
        verify(agentSecretWriter, org.mockito.Mockito.never()).writeSecret(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void registerDns_namecheapStoresFullCredentialInAgentKv() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(org.mockito.ArgumentMatchers.eq(1L), anyString()))
                .thenReturn("certping-org1-namecheap");
        when(agentSecretWriter.writeSecret(org.mockito.ArgumentMatchers.eq("certping-org1-namecheap"), anyString()))
                .thenReturn("https://example-vault.vault.azure.net/secrets/certping-org1-namecheap");
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"apiUser\":\"nc-user\",\"username\":\"nc-user\",\"apiKey\":\"nc-secret\",\"clientIp\":\"strip-me\"}");
        CredentialReferenceEntity saved = credentialReferenceService.registerDns(
                1L, "NAMECHEAP", "namecheap dns", null, credJson, null);

        org.mockito.ArgumentCaptor<String> valueCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(agentSecretWriter).writeSecret(org.mockito.ArgumentMatchers.eq("certping-org1-namecheap"), valueCaptor.capture());
        assertThat(objectMapper.readTree(valueCaptor.getValue())).isEqualTo(objectMapper.readTree(
                "{\"apiUser\":\"nc-user\",\"username\":\"nc-user\",\"apiKey\":\"nc-secret\"}"));
        assertThat(saved.getSecretHandle())
                .isEqualTo("https://example-vault.vault.azure.net/secrets/certping-org1-namecheap");
        assertThat(saved.getConfigJson()).isNull();
    }

    @Test
    void registerDns_namecheapCredJsonWithoutKvPathAndNoSecretStoreRejects() throws Exception {
        when(organizationRepository.existsById(1L)).thenReturn(true);

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"apiUser\":\"nc-user\",\"username\":\"nc-user\"}");

        // Without a vault path the pasted details go to the agent secret store; none is set up here.
        assertThatThrownBy(() -> credentialReferenceService.registerDns(
                1L, "NAMECHEAP", "namecheap dns", null, credJson, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("agent secret store is not configured");
    }

    @Test
    void registerDns_namecheapPastedWithoutVaultIsStoredForTheAgent() throws Exception {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(eq(1L), anyString())).thenReturn("org-1-cred");
        when(agentSecretWriter.writeSecret(eq("org-1-cred"), anyString())).thenReturn("local:certping-cred-1");
        when(credentialRepo.save(any(CredentialReferenceEntity.class))).thenAnswer(i -> i.getArgument(0));

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"apiUser\":\"nc-user\",\"username\":\"nc-user\",\"apiKey\":\"nc-secret\"}");

        CredentialReferenceEntity saved = credentialReferenceService.registerDns(
                1L, "NAMECHEAP", "namecheap dns", null, credJson, null);

        assertThat(saved.getSecretHandle()).isEqualTo("local:certping-cred-1");
        assertThat(CredentialReferenceService.isCertPingStoredHandle("sealed:abc")).isTrue();
        assertThat(CredentialReferenceService.isCertPingStoredHandle("https://kv/secrets/a")).isFalse();
        assertThat(CredentialReferenceService.isCertPingStoredHandle(null)).isFalse();
    }

    @Test
    void registerDeployment_withCredJson_serializesAwsPayloadAsJson() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(org.mockito.ArgumentMatchers.eq(1L), anyString()))
                .thenReturn("certping-org1-cred-abc");
        when(agentSecretWriter.writeSecret(anyString(), anyString()))
                .thenReturn("https://example-vault.vault.azure.net/secrets/certping-org1-cred-abc");
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(org.mockito.ArgumentMatchers.any(CredentialReferenceEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"accessKeyId\":\"AKIA\",\"secretAccessKey\":\"shh\",\"extra\":\"strip-me\"}");
        credentialReferenceService.registerDeployment(
                1L, "AWS_ACM", "deploy", null, null, credJson);

        org.mockito.ArgumentCaptor<String> valueCap = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(agentSecretWriter).writeSecret(anyString(), valueCap.capture());
        tools.jackson.databind.JsonNode written = objectMapper.readTree(valueCap.getValue());
        assertThat(written.get("accessKeyId").asString()).isEqualTo("AKIA");
        assertThat(written.get("secretAccessKey").asString()).isEqualTo("shh");
        assertThat(written.has("extra")).isFalse();
    }

    @Test
    void registerDns_withCredJsonWhenAgentKvNotConfigured_rejects() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(false);
        when(organizationRepository.existsById(1L)).thenReturn(true);

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree("{\"apiToken\":\"x\"}");
        assertThatThrownBy(() -> credentialReferenceService.registerDns(
                1L, "CLOUDFLARE", "d", null, credJson, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("agent secret store is not configured");
    }

    @Test
    void updateCredential_withCredJson_overwritesSecretAtExistingPath() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-rot")
                .organizationId(1L)
                .provider("AWS_ROUTE53")
                .type("DNS")
                .status("ACTIVE")
                .secretHandle("https://example-vault.vault.azure.net/secrets/certping-org1-cred-rot")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-rot", 1L))
                .thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"accessKeyId\":\"AKIA-NEW\",\"secretAccessKey\":\"rotated\"}");
        credentialReferenceService.updateCredential(1L, "cred-rot", null, null, credJson);

        // Path unchanged → secret written under the existing name so cert command emission stays identical.
        // Handle unchanged → secret overwritten at the existing handle so agent read path stays identical.
        verify(agentSecretWriter).overwriteAtHandle(
                org.mockito.ArgumentMatchers.eq("https://example-vault.vault.azure.net/secrets/certping-org1-cred-rot"),
                org.mockito.ArgumentMatchers.contains("AKIA-NEW"));
        assertThat(existing.getSecretHandle())
                .isEqualTo("https://example-vault.vault.azure.net/secrets/certping-org1-cred-rot");
        verify(renewalScheduleRepository).rearmParkedFailuresByDnsCredentialXref("cred-rot");
    }

    @Test
    void updateCredential_namecheapCredJsonUpdatesConfigWithoutOverwritingKvSecret() throws Exception {
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-nc")
                .organizationId(1L)
                .provider("NAMECHEAP")
                .type("DNS")
                .status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/namecheap-api-key")
                .configJson("{\"apiUser\":\"old\",\"username\":\"old\"}")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-nc", 1L))
                .thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"apiUser\":\"new-user\",\"username\":\"new-user\",\"apiKey\":\"must-not-store\"}");
        credentialReferenceService.updateCredential(1L, "cred-nc", null, null, credJson);

        assertThat(existing.getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/namecheap-api-key");
        assertThat(objectMapper.readTree(existing.getConfigJson()))
                .isEqualTo(objectMapper.readTree("{\"apiUser\":\"new-user\",\"username\":\"new-user\"}"));
        verify(agentSecretWriter, org.mockito.Mockito.never()).writeSecret(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void updateCredential_namecheapConfigJsonIsSanitized() throws Exception {
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-nc-config")
                .organizationId(1L)
                .provider("NAMECHEAP")
                .type("DNS")
                .status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/namecheap-api-key")
                .configJson("{\"apiUser\":\"old\",\"username\":\"old\"}")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-nc-config", 1L))
                .thenReturn(Optional.of(existing));
        when(credentialRepo.save(existing)).thenReturn(existing);

        credentialReferenceService.updateCredential(
                1L,
                "cred-nc-config",
                null,
                "{\"apiUser\":\"config-user\",\"username\":\"config-user\",\"apiKey\":\"must-not-store\"}",
                null);

        assertThat(objectMapper.readTree(existing.getConfigJson()))
                .isEqualTo(objectMapper.readTree("{\"apiUser\":\"config-user\",\"username\":\"config-user\"}"));
        assertThat(existing.getConfigJson()).doesNotContain("apiKey");
    }

    @Test
    void updateCredential_namecheapRejectsCredJsonAndConfigJsonTogether() throws Exception {
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-nc-ambiguous")
                .organizationId(1L)
                .provider("NAMECHEAP")
                .type("DNS")
                .status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/namecheap-api-key")
                .configJson("{\"apiUser\":\"old\",\"username\":\"old\"}")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-nc-ambiguous", 1L))
                .thenReturn(Optional.of(existing));

        tools.jackson.databind.JsonNode credJson = objectMapper.readTree(
                "{\"apiUser\":\"new-user\",\"username\":\"new-user\"}");

        assertThatThrownBy(() -> credentialReferenceService.updateCredential(
                1L,
                "cred-nc-ambiguous",
                null,
                "{\"apiUser\":\"config-user\",\"username\":\"config-user\"}",
                credJson))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Namecheap account details were provided twice");
    }

    @Test
    void updateCredential_credJsonWithChangedKvPath_rejects() throws Exception {
        CredentialReferenceEntity existing = CredentialReferenceEntity.builder()
                .credentialXref("cred-rot2")
                .organizationId(1L)
                .provider("CLOUDFLARE")
                .type("DNS")
                .status("ACTIVE")
                .secretHandle("https://example-vault.vault.azure.net/secrets/existing")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-rot2", 1L))
                .thenReturn(Optional.of(existing));
        tools.jackson.databind.JsonNode credJson = objectMapper.readTree("{\"apiToken\":\"x\"}");

        assertThatThrownBy(() -> credentialReferenceService.updateCredential(
                1L, "cred-rot2", "https://elsewhere.vault.azure.net/secrets/diff", null, credJson))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Cannot change secretHandle while rotating credJson");
    }

    @Test
    void delete_purgesAgentKvSecret() {
        CredentialReferenceEntity active = CredentialReferenceEntity.builder()
                .credentialXref("cred-del-x")
                .organizationId(1L)
                .provider("AWS_ROUTE53")
                .type("DNS")
                .status("ACTIVE")
                .secretHandle("https://example-vault.vault.azure.net/secrets/certping-org1-cred-del-x")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-del-x", 1L))
                .thenReturn(Optional.of(active));
        when(credentialRepo.countActiveCertsReferencingCredential("cred-del-x")).thenReturn(0L);
        when(credentialRepo.save(active)).thenReturn(active);

        credentialReferenceService.delete(1L, "cred-del-x");

        verify(agentSecretWriter).deleteIfOwned(
                "https://example-vault.vault.azure.net/secrets/certping-org1-cred-del-x");
        assertThat(active.getStatus()).isEqualTo("DELETED");
    }

    @Test
    void updateAndDeleteOfADnsCredential_areRefusedUnderTheLockWhileDnsCredentialsIsOff() {
        CredentialReferenceEntity dns = CredentialReferenceEntity.builder()
                .credentialXref("cred-dns-off").organizationId(1L).provider("AWS_ROUTE53").type("DNS")
                .status("ACTIVE").secretHandle("https://kv.vault.azure.net/secrets/dns").build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-dns-off", 1L)).thenReturn(Optional.of(dns));
        doThrow(new FeatureDisabledException(FeatureFlags.DNS_CREDENTIALS))
                .when(featureLifecycleLock)
                .lockAndAssertEnabled(1L, FeatureFlags.DNS_CREDENTIALS);

        assertThatThrownBy(() -> credentialReferenceService.updateCredential(1L, "cred-dns-off", null, null, null))
                .isInstanceOf(FeatureDisabledException.class);
        assertThatThrownBy(() -> credentialReferenceService.delete(1L, "cred-dns-off"))
                .isInstanceOf(FeatureDisabledException.class);
        verify(credentialRepo, never()).save(any());
    }

    @Test
    void registerDns_certPingWhileDnsCredentialsIsOff_takesNoDnsCredentialsLock() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(eq(1L), anyString())).thenReturn("certping-org1-cred-cp");
        when(agentSecretWriter.writeSecret(eq("certping-org1-cred-cp"), anyString()))
                .thenReturn("https://example-vault.vault.azure.net/secrets/certping-org1-cred-cp");
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(any(CredentialReferenceEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerDns(1L, "CERTPING", "example.com", null,
                objectMapper.readTree("{\"apiKey\":\"cpk_live_secret\"}"), null);

        assertThat(saved.getProvider()).isEqualTo("CERTPING");
        verify(featureLifecycleLock, never()).lockAndAssertEnabled(anyLong(), anyString());
    }

    @Test
    void registerDns_thirdPartyWhileDnsCredentialsIsOff_isRefusedUnderTheLock() {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        doThrow(new FeatureDisabledException(FeatureFlags.DNS_CREDENTIALS))
                .when(featureLifecycleLock).lockAndAssertEnabled(1L, FeatureFlags.DNS_CREDENTIALS);

        assertThatThrownBy(() -> credentialReferenceService.registerDns(1L, "CLOUDFLARE", "d", null,
                objectMapper.readTree("{\"apiToken\":\"cf-token\"}"), null))
                .isInstanceOf(FeatureDisabledException.class);
        verify(credentialRepo, never()).save(any());
    }

    @Test
    void registerDns_certPingKeepsTheKeyDetailsInItsConfig() throws Exception {
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(agentSecretWriter.buildSecretName(eq(1L), anyString())).thenReturn("certping-org1-cred-cp");
        when(agentSecretWriter.writeSecret(eq("certping-org1-cred-cp"), anyString()))
                .thenReturn("https://example-vault.vault.azure.net/secrets/certping-org1-cred-cp");
        when(organizationRepository.existsById(1L)).thenReturn(true);
        when(credentialRepo.save(any(CredentialReferenceEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        CredentialReferenceEntity saved = credentialReferenceService.registerDns(1L, "CERTPING", "example.com", null,
                objectMapper.readTree("{\"apiKey\":\"cpk_live_secret\"}"), objectMapper.readTree(CERTPING_KEY_DETAILS));

        assertThat(objectMapper.readTree(saved.getConfigJson())).isEqualTo(objectMapper.readTree(CERTPING_KEY_DETAILS));
    }

    @Test
    void registerDns_keyDetailsForAThirdPartyProvider_areRefused() throws Exception {
        when(organizationRepository.existsById(1L)).thenReturn(true);
        tools.jackson.databind.JsonNode details = objectMapper.readTree(CERTPING_KEY_DETAILS);

        assertThatThrownBy(() -> credentialReferenceService.registerDns(1L, "CLOUDFLARE", "d", null,
                objectMapper.readTree("{\"apiToken\":\"cf-token\"}"), details))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Configuration details are only accepted for CertPing DNS credentials.");
        verify(credentialRepo, never()).save(any());
    }

    @Test
    void updateCredential_certPingReplacesTheKeyDetailsAndRearmsItsRenewals() throws Exception {
        CredentialReferenceEntity certPing = CredentialReferenceEntity.builder()
                .credentialXref("cred-cp").organizationId(1L).provider("CERTPING").type("DNS").status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/cp")
                .configJson("{\"tokenId\":40,\"tokenPrefix\":\"cpk_live_old1old1\",\"expiresAt\":\"2026-10-01T00:00:00Z\"}")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-cp", 1L)).thenReturn(Optional.of(certPing));
        when(credentialRepo.save(certPing)).thenReturn(certPing);

        credentialReferenceService.updateCredential(1L, "cred-cp", null, CERTPING_KEY_DETAILS, null);

        assertThat(objectMapper.readTree(certPing.getConfigJson())).isEqualTo(objectMapper.readTree(CERTPING_KEY_DETAILS));
        verify(renewalScheduleRepository).rearmParkedFailuresByDnsCredentialXref("cred-cp");
    }

    @Test
    void updateCredential_aNewCertPingKeyWithoutItsDetails_dropsTheReplacedKeysDetails() throws Exception {
        CredentialReferenceEntity certPing = CredentialReferenceEntity.builder()
                .credentialXref("cred-cp").organizationId(1L).provider("CERTPING").type("DNS").status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/cp")
                .configJson("{\"tokenId\":40,\"tokenPrefix\":\"cpk_live_old1old1\",\"expiresAt\":\"2026-10-01T00:00:00Z\"}")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-cp", 1L)).thenReturn(Optional.of(certPing));
        when(agentSecretWriter.isAvailable()).thenReturn(true);
        when(credentialRepo.save(certPing)).thenReturn(certPing);

        credentialReferenceService.updateCredential(1L, "cred-cp", null, null,
                objectMapper.readTree("{\"apiKey\":\"cpk_live_new\"}"));

        assertThat(certPing.getConfigJson()).isNull();
        verify(agentSecretWriter).overwriteAtHandle(eq("https://kv.vault.azure.net/secrets/cp"), anyString());
    }

    @Test
    void updateCredential_aNewKvPathForACertPingKeyWithoutItsDetails_dropsTheReplacedKeysDetails() {
        CredentialReferenceEntity certPing = certPingWithDetails();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-cp", 1L)).thenReturn(Optional.of(certPing));
        when(credentialRepo.save(certPing)).thenReturn(certPing);

        credentialReferenceService.updateCredential(1L, "cred-cp", "https://kv.vault.azure.net/secrets/cp-2", null, null);

        assertThat(certPing.getConfigJson()).isNull();
        assertThat(certPing.getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/cp-2");
    }

    @Test
    void updateCredential_theSameKvPathForACertPingKey_keepsItsDetails() {
        CredentialReferenceEntity certPing = certPingWithDetails();
        String details = certPing.getConfigJson();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-cp", 1L)).thenReturn(Optional.of(certPing));
        when(credentialRepo.save(certPing)).thenReturn(certPing);

        credentialReferenceService.updateCredential(1L, "cred-cp", "https://kv.vault.azure.net/secrets/cp", null, null);

        assertThat(certPing.getConfigJson()).isEqualTo(details);
    }

    @Test
    void updateCredential_incompleteCertPingKeyDetails_areRefusedAndNothingIsSaved() {
        CredentialReferenceEntity certPing = CredentialReferenceEntity.builder()
                .credentialXref("cred-cp").organizationId(1L).provider("CERTPING").type("DNS").status("ACTIVE").build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-cp", 1L)).thenReturn(Optional.of(certPing));

        assertThatThrownBy(() -> credentialReferenceService.updateCredential(1L, "cred-cp", null,
                "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\"}", null))
                .isInstanceOf(CredentialRejectedException.class)
                .extracting("code").isEqualTo(CredentialRejectedException.DETAILS_INVALID);
        assertThat(certPing.getConfigJson()).isNull();
        verify(credentialRepo, never()).save(any());
    }

    @Test
    void updateAndDeleteOfACertPingDnsCredential_takeNoDnsCredentialsLock() {
        CredentialReferenceEntity certPing = CredentialReferenceEntity.builder()
                .credentialXref("cred-cp").organizationId(1L).provider("CERTPING").type("DNS").status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/cp").build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-cp", 1L)).thenReturn(Optional.of(certPing));
        when(credentialRepo.countActiveCertsReferencingCredential("cred-cp")).thenReturn(0L);
        when(credentialRepo.save(certPing)).thenReturn(certPing);

        credentialReferenceService.updateCredential(1L, "cred-cp", "https://kv.vault.azure.net/secrets/cp-2", null, null);
        credentialReferenceService.delete(1L, "cred-cp");

        verify(featureLifecycleLock, never()).lockAndAssertEnabled(anyLong(), anyString());
    }

    @Test
    void deleteOfADeploymentCredential_staysUnderCredentialsManagement() {
        CredentialReferenceEntity deployment = CredentialReferenceEntity.builder()
                .credentialXref("cred-dep").organizationId(1L).provider("AZURE_KV").type("DEPLOYMENT")
                .status("ACTIVE").secretHandle("https://kv.vault.azure.net/secrets/dep").build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-dep", 1L)).thenReturn(Optional.of(deployment));
        when(credentialRepo.countActiveCertsReferencingCredential("cred-dep")).thenReturn(0L);
        when(credentialRepo.save(deployment)).thenReturn(deployment);

        credentialReferenceService.delete(1L, "cred-dep");

        verify(featureLifecycleLock).lockAndAssertEnabled(1L, FeatureFlags.CREDENTIALS_MANAGEMENT);
    }

    @Test
    void updateCredential_rejectsDeletedCredentialBeforeSave() {
        CredentialReferenceEntity deleted = CredentialReferenceEntity.builder()
                .credentialXref("cred-del-1")
                .organizationId(1L)
                .provider("KUBERNETES_SECRETS")
                .type("DEPLOYMENT")
                .status("DELETED")
                .secretHandle("https://kv.vault.azure.net/secrets/old")
                .build();
        when(credentialRepo.findByCredentialXrefAndOrganizationId("cred-del-1", 1L))
                .thenReturn(Optional.of(deleted));

        assertThatThrownBy(() -> credentialReferenceService.updateCredential(
                1L,
                "cred-del-1",
                "https://kv.vault.azure.net/secrets/new",
                "{\"authMethod\":\"AWS\",\"clusterName\":\"prod\",\"namespaces\":\"all_namespaces\"}",
                null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Cannot update a deleted credential reference");

        verifyNoInteractions(kubernetesConfigValidator);
        verify(credentialRepo).findByCredentialXrefAndOrganizationId(anyString(), org.mockito.ArgumentMatchers.eq(1L));
    }


    private static CredentialReferenceEntity certPingWithDetails() {
        return CredentialReferenceEntity.builder()
                .credentialXref("cred-cp").organizationId(1L).provider("CERTPING").type("DNS").status("ACTIVE")
                .secretHandle("https://kv.vault.azure.net/secrets/cp")
                .configJson("{\"tokenId\":40,\"tokenPrefix\":\"cpk_live_old1old1\",\"expiresAt\":\"2026-10-01T00:00:00Z\"}")
                .build();
    }
}
