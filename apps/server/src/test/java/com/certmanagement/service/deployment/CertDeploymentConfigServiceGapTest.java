// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.CertDeploymentConfigEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.service.deployment.config.DeploymentResultMerger;
import com.certmanagement.service.deployment.config.DeploymentResultMergerRegistry;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidatorRegistry;
import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Coverage gap tests for {@link CertDeploymentConfigService} — focuses on the
 * validation/error branches in credential-scope parsing, namespace-secret-map
 * validation, and the early-return guards.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CertDeploymentConfigServiceGapTest {

    private static final Long ORG = 1L;
    private static final Long UDC = 10L;
    private static final Long CRED_ID = 20L;

    @Mock private CertDeploymentConfigRepository repository;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @Mock private KubernetesNamespaceNameValidator namespaceNameValidator;
    @Mock private KubernetesSecretNameValidator secretNameValidator;
    @Mock private DeploymentResultMergerRegistry resultMergerRegistry;
    @Mock private DeploymentTargetsValidatorRegistry targetsValidatorRegistry;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private CertDeploymentConfigService service;

    @BeforeEach
    void setUp() {
        service = new CertDeploymentConfigService(
                repository, credentialReferenceRepository,
                namespaceNameValidator, secretNameValidator,
                resultMergerRegistry, targetsValidatorRegistry, objectMapper);
    }

    private CredentialReferenceEntity k8sCred(String configJson) {
        return CredentialReferenceEntity.builder()
                .id(CRED_ID).credentialXref("cred-1").provider("KUBERNETES_SECRETS")
                .configJson(configJson).build();
    }

    private JsonNode node(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ── requireReconciledConfigJson guards ──────────────────────────────

    @Test
    void requireReconciled_nonK8sProvider_throws() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .id(CRED_ID).provider("AWS_ACM").build();
        assertThatThrownBy(() -> service.requireReconciledConfigJson(ORG, UDC, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("KUBERNETES_SECRETS");
    }

    @Test
    void requireReconciled_nullCredentialId_throws() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("KUBERNETES_SECRETS").build();
        assertThatThrownBy(() -> service.requireReconciledConfigJson(ORG, UDC, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("invalid");
    }

    // ── findReconciledConfigJson branches ───────────────────────────────

    @Test
    void findReconciled_nullCredentialId_returnsEmpty() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("KUBERNETES_SECRETS").build();
        assertThat(service.findReconciledConfigJson(ORG, UDC, cred)).isEmpty();
    }

    @Test
    void findReconciled_notFound_returnsEmpty() {
        CredentialReferenceEntity cred = k8sCred("{}");
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG, UDC, CRED_ID)).thenReturn(Optional.empty());
        assertThat(service.findReconciledConfigJson(ORG, UDC, cred)).isEmpty();
    }

    @Test
    void findReconciled_nonK8s_returnsConfigJsonAsIs() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .id(CRED_ID).provider("AWS_ACM").build();
        CertDeploymentConfigEntity entity = CertDeploymentConfigEntity.builder()
                .configJson("{\"targets\":{}}").build();
        when(repository.findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                ORG, UDC, CRED_ID)).thenReturn(Optional.of(entity));
        assertThat(service.findReconciledConfigJson(ORG, UDC, cred))
                .contains("{\"targets\":{}}");
    }

    // ── validateAndUpsertKubernetesConfig guards ───────────────────────

    @Test
    void k8sUpsert_nonK8sProvider_throws() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .id(CRED_ID).provider("AWS_ACM").build();
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{}")))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void k8sUpsert_nullConfig_throws() {
        CredentialReferenceEntity cred = k8sCred("{}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("required");
    }

    @Test
    void k8sUpsert_nullCredentialId_throws() {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("KUBERNETES_SECRETS").configJson("{}").build();
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("invalid");
    }

    // ── parseCredentialScope error branches (via k8s upsert) ───────────

    @Test
    void scope_missingAuthMethod_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"clusterName\":\"c\",\"namespaces\":\"all_namespaces\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"s\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("authMethod is required");
    }

    @Test
    void scope_missingClusterName_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"namespaces\":\"all_namespaces\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"s\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("clusterName is required");
    }

    @Test
    void scope_namespacesStringNotAllNamespaces_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":\"some\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"s\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("all_namespaces");
    }

    @Test
    void scope_namespacesEmptyArray_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[]}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"s\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty array");
    }

    @Test
    void scope_namespacesArrayWithBlank_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"\"]}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"s\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty strings");
    }

    @Test
    void scope_invalidJson_throws() {
        CredentialReferenceEntity cred = k8sCred("not json");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"s\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("format");
    }

    // ── nsSecretMap validation branches ────────────────────────────────

    @Test
    void nsMap_objectFormButCredScoped_throws() {
        // credential allows specific namespaces (allowed != null) but request is object form
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"s\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("namespace list");
    }

    @Test
    void nsMap_objectKeyNotAllNamespaces_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":\"all_namespaces\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"dev\":\"s\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("all_namespaces");
    }

    @Test
    void nsMap_objectMultipleKeys_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":\"all_namespaces\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"s\",\"x\":\"y\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("only all_namespaces");
    }

    @Test
    void nsMap_allNamespacesBlankSecret_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":\"all_namespaces\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty secret");
    }

    @Test
    void nsMap_allNamespacesInvalidSecret_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":\"all_namespaces\"}");
        when(secretNameValidator.isValid("BAD")).thenReturn(false);
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("{\"all_namespaces\":\"BAD\"}")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Invalid kubernetes secret");
    }

    @Test
    void nsMap_arrayButCredAllNamespaces_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":\"all_namespaces\"}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"s\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("all_namespaces");
    }

    @Test
    void nsMap_arrayItemNotSingleMapping_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"s\",\"extra\":\"x\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("exactly one");
    }

    @Test
    void nsMap_arrayBlankSecret_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty strings");
    }

    @Test
    void nsMap_arrayInvalidNamespace_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        when(namespaceNameValidator.isValid("dev")).thenReturn(false);
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"s\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Invalid kubernetes namespace");
    }

    @Test
    void nsMap_arrayNamespaceNotAllowed_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        when(namespaceNameValidator.isValid("prod")).thenReturn(true);
        when(secretNameValidator.isValid("s")).thenReturn(true);
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"prod\":\"s\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not allowed");
    }

    @Test
    void nsMap_arrayDuplicateNamespace_throws() {
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        when(namespaceNameValidator.isValid("dev")).thenReturn(true);
        when(secretNameValidator.isValid(any())).thenReturn(true);
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[{\"dev\":\"s1\"},{\"dev\":\"s2\"}]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void nsMap_arrayEmptyAfterArrayBranch_throws() {
        // empty array -> buildValidatedNsMaps array branch with empty
        CredentialReferenceEntity cred = k8sCred("{\"authMethod\":\"SA\",\"clusterName\":\"c\",\"namespaces\":[\"dev\"]}");
        assertThatThrownBy(() -> service.validateAndUpsertKubernetesConfig(ORG, UDC, cred, node("[]")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty namespace map");
    }

    // ── mergeDeploymentResultFromAgent credential-missing branch ───────

    @Test
    void merge_credNotFound_skips() {
        when(resultMergerRegistry.find(TargetType.AWS_ACM))
                .thenReturn(Optional.of(mock(DeploymentResultMerger.class)));
        when(credentialReferenceRepository.findByCredentialXref("xref")).thenReturn(Optional.empty());

        service.mergeDeploymentResultFromAgent(ORG, UDC, "xref", "AWS_ACM", "{\"a\":1}");

        verify(repository, never()).save(any());
    }

    @Test
    void merge_blankPerDomainJson_skips() {
        service.mergeDeploymentResultFromAgent(ORG, UDC, "xref", "AWS_ACM", "  ");
        verifyNoInteractions(resultMergerRegistry);
    }
}
