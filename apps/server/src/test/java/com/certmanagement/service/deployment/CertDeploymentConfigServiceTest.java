// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.CertDeploymentConfigEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.service.deployment.config.DeploymentResultMerger;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertDeploymentConfigServiceTest {

    private static final Long ORG_ID = 1L;
    private static final Long UDC_ID = 10L;
    private static final Long DEPLOYMENT_CREDENTIAL_ID = 20L;

    @Mock
    private CertDeploymentConfigRepository repository;

    @Mock
    private CredentialReferenceRepository credentialReferenceRepository;

    @Mock
    private KubernetesNamespaceNameValidator namespaceNameValidator;

    @Mock
    private KubernetesSecretNameValidator secretNameValidator;

    @Mock
    private com.certmanagement.service.deployment.config.DeploymentResultMergerRegistry resultMergerRegistry;

    @Mock
    private com.certmanagement.service.deployment.config.DeploymentTargetsValidatorRegistry targetsValidatorRegistry;

    private CertDeploymentConfigService service;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @BeforeEach
    void setUp() {
        service = new CertDeploymentConfigService(
                                repository,
                                credentialReferenceRepository,
                                namespaceNameValidator,
                                secretNameValidator,
                                resultMergerRegistry,
                                targetsValidatorRegistry,
                                objectMapper);
    }

    @Test
    void validateAndUpsertKubernetesConfig_storesFlatAgentContract() throws Exception {
        CredentialReferenceEntity deploymentCredential = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-1")
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"dev-cluster\",\"namespaces\":[\"dev\"]}")
                .build();

        when(namespaceNameValidator.isValid("dev")).thenReturn(true);
        when(secretNameValidator.isValid("example-dev-tls")).thenReturn(true);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        String stored = service.validateAndUpsertKubernetesConfig(
                ORG_ID,
                UDC_ID,
                deploymentCredential,
                objectMapper.readTree("[{\"dev\":\"example-dev-tls\"}]"));

        assertThat(stored)
                .isEqualTo("{\"authProvider\":\"SA_INCLUSTER\",\"clusterName\":\"dev-cluster\",\"nsMaps\":[{\"dev\":\"example-dev-tls\"}]}");

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getConfigJson()).isEqualTo(stored);
    }

    @Test
    void requireReconciledConfigJson_refreshesAuthAndClusterFromCredentialReference() {
        CredentialReferenceEntity deploymentCredential = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-1")
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"new-cluster\",\"namespaces\":[\"dev\"]}")
                .build();
        CertDeploymentConfigEntity entity = CertDeploymentConfigEntity.builder()
                .organizationId(ORG_ID)
                .userDomainCertId(UDC_ID)
                .deploymentCredentialId(DEPLOYMENT_CREDENTIAL_ID)
                .deploymentCredentialXref("cred-1")
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authProvider\":\"AWS\",\"clusterName\":\"old-cluster\",\"nsMaps\":[{\"dev\":\"example-dev-tls\"}]}")
                .build();

        when(namespaceNameValidator.isValid("dev")).thenReturn(true);
        when(secretNameValidator.isValid("example-dev-tls")).thenReturn(true);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.of(entity));
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        String reconciled = service.requireReconciledConfigJson(ORG_ID, UDC_ID, deploymentCredential);

        assertThat(reconciled)
                .isEqualTo("{\"authProvider\":\"SA_INCLUSTER\",\"clusterName\":\"new-cluster\",\"nsMaps\":[{\"dev\":\"example-dev-tls\"}]}");
        verify(repository).save(any(CertDeploymentConfigEntity.class));
    }

    @Test
    void requireReconciledConfigJson_failsWhenStoredNsMapViolatesCredentialNamespaces() {
        CredentialReferenceEntity deploymentCredential = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-1")
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"cluster\",\"namespaces\":[\"dev\"]}")
                .build();
        CertDeploymentConfigEntity entity = CertDeploymentConfigEntity.builder()
                .organizationId(ORG_ID)
                .userDomainCertId(UDC_ID)
                .deploymentCredentialId(DEPLOYMENT_CREDENTIAL_ID)
                .deploymentCredentialXref("cred-1")
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authProvider\":\"SA_INCLUSTER\",\"clusterName\":\"cluster\",\"nsMaps\":[{\"prod\":\"example-prod-tls\"}]}")
                .build();

        when(namespaceNameValidator.isValid("prod")).thenReturn(true);
        when(secretNameValidator.isValid("example-prod-tls")).thenReturn(true);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.of(entity));

        assertThatThrownBy(() -> service.requireReconciledConfigJson(ORG_ID, UDC_ID, deploymentCredential))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("is not allowed by deployment credential config");
    }

    @Test
    void requireReconciledConfigJson_throwsWhenMissing() {
        CredentialReferenceEntity deploymentCredential = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"cluster\",\"namespaces\":[\"dev\"]}")
                .build();
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.requireReconciledConfigJson(ORG_ID, UDC_ID, deploymentCredential))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Default kubernetes deployment config not found");
    }

    @Test
    void mergeDeploymentResultFromAgent_upsertsAwsSlice() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-x")
                .provider("AWS_ACM")
                .build();
        DeploymentResultMerger merger = mock(DeploymentResultMerger.class);
        String payload = "{\"arn\":\"arn:aws:acm:us-east-1:1:certificate/abc\"}";
        JsonNode merged = readJson(payload);
        when(credentialReferenceRepository.findByCredentialXref("cred-x")).thenReturn(Optional.of(cred));
        when(resultMergerRegistry.find(TargetType.AWS_ACM)).thenReturn(Optional.of(merger));
        when(merger.merge(any(JsonNode.class), any(JsonNode.class))).thenReturn(merged);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.mergeDeploymentResultFromAgent(ORG_ID, UDC_ID, "cred-x", "AWS_ACM", payload);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        JsonNode stored = readJson(captor.getValue().getConfigJson());
        assertThat(stored.get("result").get("arn").asString())
                .isEqualTo("arn:aws:acm:us-east-1:1:certificate/abc");
    }

    @Test
    void mergeDeploymentResultFromAgent_upsertsAzureAfdCertNameSlice() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-az")
                .provider("AZURE_AFD")
                .build();
        DeploymentResultMerger merger = mock(DeploymentResultMerger.class);
        String payload = "{\"certificateName\":\"afd-example-com\"}";
        JsonNode merged = readJson(payload);
        when(credentialReferenceRepository.findByCredentialXref("cred-az")).thenReturn(Optional.of(cred));
        when(resultMergerRegistry.find(TargetType.AZURE_AFD)).thenReturn(Optional.of(merger));
        when(merger.merge(any(JsonNode.class), any(JsonNode.class))).thenReturn(merged);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.mergeDeploymentResultFromAgent(ORG_ID, UDC_ID, "cred-az", "AZURE_AFD", payload);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        JsonNode stored = readJson(captor.getValue().getConfigJson());
        assertThat(stored.get("result").get("certificateName").asString())
                .isEqualTo("afd-example-com");
    }

    @Test
    void mergeDeploymentResultFromAgent_upsertsGcpConfigJsonBlob() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-gcp")
                .provider("GCP_CERT_MANAGER")
                .build();
                DeploymentResultMerger merger = mock(DeploymentResultMerger.class);
                String blob = "{\"certificateResourceName\":\"projects/p/locations/global/certificates/c1\",\"certificateMapName\":\"m\"}";
                JsonNode merged = readJson(blob);
        when(credentialReferenceRepository.findByCredentialXref("cred-gcp")).thenReturn(Optional.of(cred));
                when(resultMergerRegistry.find(TargetType.GCP_CERT_MANAGER)).thenReturn(Optional.of(merger));
                when(merger.merge(any(JsonNode.class), any(JsonNode.class))).thenReturn(merged);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.mergeDeploymentResultFromAgent(ORG_ID, UDC_ID, "cred-gcp", "GCP_CERT_MANAGER", blob);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
                JsonNode stored = readJson(captor.getValue().getConfigJson());
                assertThat(stored.get("result").get("certificateResourceName").asString())
                                .isEqualTo("projects/p/locations/global/certificates/c1");
                assertThat(stored.get("result").get("certificateMapName").asString()).isEqualTo("m");
    }

    @Test
    void mergeDeploymentResultFromAgent_noMergerRegistered_skipsWithoutSaving() {
        when(resultMergerRegistry.find(TargetType.CLOUDFLARE_EDGE)).thenReturn(Optional.empty());

        service.mergeDeploymentResultFromAgent(
                ORG_ID, UDC_ID, "cred-x", "CLOUDFLARE_EDGE", "{\"certId\":\"abc\"}");

        verify(repository, never()).save(any());
        verify(credentialReferenceRepository, never()).findByCredentialXref(any());
    }

    @Test
    void mergeDeploymentResultFromAgent_unknownTargetType_skipsWithoutSaving() {
        service.mergeDeploymentResultFromAgent(
                ORG_ID, UDC_ID, "cred-x", "NOT_A_REAL_TYPE", "{\"foo\":\"bar\"}");

        verify(resultMergerRegistry, never()).find(any());
        verify(repository, never()).save(any());
    }

    @Test
    void mergeDeploymentResultFromAgent_nullOrgId_skipsWithoutSaving() {
        service.mergeDeploymentResultFromAgent(
                null, UDC_ID, "cred-x", "AWS_ACM", "{\"arn\":\"arn:x\"}");

        verify(resultMergerRegistry, never()).find(any());
        verify(repository, never()).save(any());
    }

    @Test
    void mergeDeploymentResultFromAgent_blankCredXref_skipsWithoutSaving() {
        service.mergeDeploymentResultFromAgent(
                ORG_ID, UDC_ID, "  ", "AWS_ACM", "{\"arn\":\"arn:x\"}");

        verify(resultMergerRegistry, never()).find(any());
        verify(repository, never()).save(any());
    }

    // ---- upsertGenericTargets ----

    @Test
    void upsertGenericTargets_nullTargets_storesEnvelopeWithEmptyTargets() {
        CredentialReferenceEntity cred = buildDeploymentCred("AWS_ACM");
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.upsertGenericTargets(ORG_ID, UDC_ID, cred, null);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getConfigJson()).isEqualTo("{\"targets\":{},\"result\":{}}");
    }

    @Test
    void upsertGenericTargets_withRegisteredValidator_validatesAndSaves() throws Exception {
        CredentialReferenceEntity cred = buildDeploymentCred("AZURE_AFD");
        JsonNode requestedTargets = objectMapper.readTree("{\"customDomains\":[\"api.example.com\"]}");
        JsonNode validatedTargets = objectMapper.readTree("{\"customDomains\":[\"api.example.com\"]}");
        DeploymentTargetsValidator validator = mock(DeploymentTargetsValidator.class);

        when(targetsValidatorRegistry.find(TargetType.AZURE_AFD)).thenReturn(Optional.of(validator));
        when(validator.validate(any(), any())).thenReturn(validatedTargets);
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.upsertGenericTargets(ORG_ID, UDC_ID, cred, requestedTargets);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        JsonNode stored = readJson(captor.getValue().getConfigJson());
        assertThat(stored.get("targets").get("customDomains").get(0).asString()).isEqualTo("api.example.com");
        assertThat(stored.get("result").isEmpty()).isTrue();
    }

    @Test
    void upsertGenericTargets_noValidatorRegistered_savesTargetsUnvalidated() throws Exception {
        CredentialReferenceEntity cred = buildDeploymentCred("CLOUDFLARE_EDGE");
        JsonNode requestedTargets = objectMapper.readTree("{\"zones\":[{\"zoneId\":\"abc\"}]}");

        when(targetsValidatorRegistry.find(TargetType.CLOUDFLARE_EDGE)).thenReturn(Optional.empty());
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.upsertGenericTargets(ORG_ID, UDC_ID, cred, requestedTargets);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        JsonNode stored = readJson(captor.getValue().getConfigJson());
        assertThat(stored.get("targets").get("zones").get(0).get("zoneId").asString()).isEqualTo("abc");
    }

    @Test
    void upsertGenericTargets_preservesExistingResultWhenUpdatingTargets() throws Exception {
        CredentialReferenceEntity cred = buildDeploymentCred("AWS_ACM");
        JsonNode requestedTargets = objectMapper.readTree("{\"newField\":\"value\"}");
        String existingJson = "{\"targets\":{\"old\":\"data\"},\"result\":{\"arn\":\"arn:aws:acm:us-east-1:1:certificate/abc\"}}";

        CertDeploymentConfigEntity existing = CertDeploymentConfigEntity.builder()
                .organizationId(ORG_ID).userDomainCertId(UDC_ID)
                .deploymentCredentialId(DEPLOYMENT_CREDENTIAL_ID)
                .configJson(existingJson).build();

        when(targetsValidatorRegistry.find(TargetType.AWS_ACM)).thenReturn(Optional.empty());
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG_ID, UDC_ID, DEPLOYMENT_CREDENTIAL_ID)).thenReturn(Optional.of(existing));
        when(repository.save(any(CertDeploymentConfigEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.upsertGenericTargets(ORG_ID, UDC_ID, cred, requestedTargets);

        ArgumentCaptor<CertDeploymentConfigEntity> captor = ArgumentCaptor.forClass(CertDeploymentConfigEntity.class);
        verify(repository).save(captor.capture());
        JsonNode stored = readJson(captor.getValue().getConfigJson());
        // targets updated, result preserved
        assertThat(stored.get("targets").get("newField").asString()).isEqualTo("value");
        assertThat(stored.get("result").get("arn").asString()).isEqualTo("arn:aws:acm:us-east-1:1:certificate/abc");
    }

    @Test
    void upsertGenericTargets_kubernetesProvider_throwsBadRequest() {
        CredentialReferenceEntity cred = buildDeploymentCred("KUBERNETES_SECRETS");

        assertThatThrownBy(() -> service.upsertGenericTargets(ORG_ID, UDC_ID, cred, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("KUBERNETES_SECRETS");
    }

    @Test
    void upsertGenericTargets_unknownProvider_throwsBadRequest() {
        CredentialReferenceEntity cred = buildDeploymentCred("NOT_REAL_PROVIDER");

        assertThatThrownBy(() -> service.upsertGenericTargets(ORG_ID, UDC_ID, cred, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Unknown deployment provider");
    }

    // ---- helpers ----

    private CredentialReferenceEntity buildDeploymentCred(String provider) {
        return CredentialReferenceEntity.builder()
                .id(DEPLOYMENT_CREDENTIAL_ID)
                .credentialXref("cred-x")
                .provider(provider)
                .build();
    }

    private JsonNode readJson(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid test JSON", e);
        }
    }
}
