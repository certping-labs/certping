// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesAuthService;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesSecretService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.function.Supplier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AzureAgcDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private KubernetesSecretService kubernetesSecretService;
    @Mock private KubernetesAuthService kubernetesAuthService;

    private AzureAgcDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"tenantId\":\"00000000-0000-0000-0000-000000000002\"," +
            "\"subscriptionId\":\"00000000-0000-0000-0000-000000000003\"," +
            "\"resourceGroup\":\"rg-prod\"," +
            "\"clusterAuthMode\":\"SA_INCLUSTER\"," +
            "\"clusterName\":\"aks-prod\"," +
            "\"agcNamespace\":\"alb-system\"," +
            "\"apiStyle\":\"GATEWAY_API\"," +
            "\"secretNamespaces\":[\"app-prod\",\"app-edge\"]}";

    private static final String TARGETS_JSON =
            "{\"secrets\":[{\"namespace\":\"app-prod\",\"secretName\":\"tls-secret-api\"}]}";

    @BeforeEach
    void setUp() {
        adapter = new AzureAgcDeploymentAdapter(
                secretStore,
                kubernetesSecretService,
                kubernetesAuthService,
                JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingClusterName_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON.replace("\"clusterName\":\"aks-prod\",", ""));
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("clusterName");
    }

    @Test
    void deploy_missingSecretNamespaces_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"clusterAuthMode\":\"SA_INCLUSTER\"," +
                "\"clusterName\":\"aks-prod\"," +
                "\"agcNamespace\":\"alb-system\"}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("secretNamespaces");
    }

    @Test
    void deploy_emptySecrets_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"secrets\":[]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_namespaceNotInScope_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"secrets\":[{\"namespace\":\"unknown-ns\",\"secretName\":\"tls-1\"}]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("not in the credential's scope.secretNamespaces");
    }

    @Test
    void deploy_duplicateSecretRef_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"secrets\":[" +
                "{\"namespace\":\"app-prod\",\"secretName\":\"tls-1\"}," +
                "{\"namespace\":\"app-prod\",\"secretName\":\"tls-1\"}" +
                "]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("Duplicate");
    }

    @Test
    void deploy_invalidTargetsJson_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_invalidApiStyle_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON.replace("\"GATEWAY_API\"", "\"INVALID\""));
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("apiStyle");
    }

    @Test
    void deploy_inCluster_writesSecretsAndReturnsResult() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        1,
                        List.of("app-prod/tls-secret-api"),
                        List.of(new KubernetesSecretService.AppliedSecret(
                                "app-prod", "tls-secret-api", "rv-123", "uid-abc"))));

        var result = adapter.deploy(buildBundle(), msg);

        assertThat(result.targetResourceId()).startsWith("agc://aks-prod/alb-system/tls-secrets/");
        assertThat(result.configJson()).contains("\"clusterName\":\"aks-prod\"");
        assertThat(result.configJson()).contains("\"agcNamespace\":\"alb-system\"");
        assertThat(result.configJson()).contains("\"secretName\":\"tls-secret-api\"");
        assertThat(result.configJson()).contains("\"resourceVersion\":\"rv-123\"");

        verify(kubernetesSecretService).deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString());
    }

    @Test
    void deploy_multipleNamespaces_callsServicePerNamespace() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"secrets\":[" +
                "{\"namespace\":\"app-prod\",\"secretName\":\"tls-1\"}," +
                "{\"namespace\":\"app-edge\",\"secretName\":\"tls-1\"}" +
                "]}");

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        1, List.of("ns/tls-1"), List.of()));

        var result = adapter.deploy(buildBundle(), msg);

        assertThat(result.targetResourceId()).contains("tls-secrets/2");
    }

    @Test
    void validateScope_allFieldsPresent_doesNotThrow() {
        AzureAgcScope scope = new AzureAgcScope(
                "t", "s", null, null, "rg",
                "AZURE", "aks-prod", "alb-system", "GATEWAY_API",
                List.of("app-prod"));
        adapter.validateScope(scope);
    }

    @Test
    void validateTargets_subsetOfScope_returnsRefs() {
        AzureAgcScope scope = new AzureAgcScope(
                "t", "s", null, null, "rg",
                "AZURE", "aks-prod", "alb-system", "GATEWAY_API",
                List.of("app-prod", "app-edge"));
        AzureAgcTargets targets = new AzureAgcTargets(List.of(
                new AzureAgcTargets.SecretRef("app-prod", "tls-www")));

        List<AzureAgcTargets.SecretRef> result = adapter.validateTargets(targets, scope);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).namespace()).isEqualTo("app-prod");
    }

    @Test
    void deploy_azureAuthMode_invokesAuthSupplier_andReachesKubernetesService() {
        // clusterAuthMode = AZURE → buildAuthConfig calls kubernetesAuthService.resolveAzureAuthForAgc.
        // We verify by having the mock invoke the supplier (Answer captures argument).
        String azureScope = SCOPE_JSON.replace("\"SA_INCLUSTER\"", "\"AZURE\"");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(azureScope);
        msg.setTargetsJson(TARGETS_JSON);
        when(secretStore.read(anyString()))
                .thenReturn("{\"clientId\":\"00000000-0000-0000-0000-000000000001\",\"clientSecret\":\"s3cret\"}");

        KubernetesSecretService.KubernetesAuthConfig authResult =
                KubernetesSecretService.KubernetesAuthConfig.forInCluster();
        when(kubernetesAuthService.resolveAzureAuthForAgc(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(authResult);

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    @SuppressWarnings("unchecked")
                    Supplier<KubernetesSecretService.KubernetesAuthConfig> supplier =
                            (Supplier<KubernetesSecretService.KubernetesAuthConfig>) inv.getArgument(2);
                    // Invoke the lambda to exercise buildAuthConfig (AZURE branch)
                    supplier.get();
                    return new KubernetesSecretService.KubernetesDeploymentSummary(
                            1, List.of("app-prod/tls-secret-api"),
                            List.of(new KubernetesSecretService.AppliedSecret(
                                    "app-prod", "tls-secret-api", "rv-1", "uid-1")));
                });

        var result = adapter.deploy(buildBundle(), msg);
        assertThat(result).isNotNull();
        // Confirm resolveAzureAuthForAgc was invoked
        verify(kubernetesAuthService).resolveAzureAuthForAgc(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void deploy_blankDomainInMessage_fallsBackToPemExtractionThenUnknown() {
        // Empty domain + unparseable PEM → "unknown"
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setDomain("   ");

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        1, List.of("app-prod/tls-secret-api"),
                        List.of(new KubernetesSecretService.AppliedSecret(
                                "app-prod", "tls-secret-api", null, null))));

        var result = adapter.deploy(buildBundle(), msg);
        assertThat(result).isNotNull();
    }

    @Test
    void deploy_lowercaseApiStyleGateway_accepted() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON.replace("\"GATEWAY_API\"", "\"gateway\""));
        msg.setTargetsJson(TARGETS_JSON);

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        1, List.of("a/b"), List.of()));

        assertThat(adapter.deploy(buildBundle(), msg)).isNotNull();
    }

    @Test
    void deploy_apiStyleIngress_accepted() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON.replace("\"GATEWAY_API\"", "\"INGRESS\""));
        msg.setTargetsJson(TARGETS_JSON);

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        1, List.of("a/b"), List.of()));

        assertThat(adapter.deploy(buildBundle(), msg)).isNotNull();
    }

    @Test
    void deploy_blankApiStyle_treatedAsDefaultAndAccepted() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON.replace("\"apiStyle\":\"GATEWAY_API\",", "\"apiStyle\":\"\","));
        msg.setTargetsJson(TARGETS_JSON);

        when(kubernetesSecretService.deployTlsSecretsForNamespace(
                any(), anyString(), any(), anyBoolean(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        1, List.of("a/b"), List.of()));

        assertThat(adapter.deploy(buildBundle(), msg)).isNotNull();
    }

    @Test
    void deploy_blankNamespaceInTargets_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"secrets\":[{\"namespace\":\"\",\"secretName\":\"tls\"}]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("namespace");
    }

    @Test
    void deploy_blankSecretNameInTargets_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"secrets\":[{\"namespace\":\"app-prod\",\"secretName\":\"\"}]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("secretName");
    }

    @Test
    void deploy_missingAgcNamespace_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON.replace("\"agcNamespace\":\"alb-system\",", ""));
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("agcNamespace");
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-agc-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AZURE_APP_GW_CONTAINERS);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/agc-cred");
        return msg;
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                """
                -----BEGIN CERTIFICATE-----
                MIILeaf==
                -----END CERTIFICATE-----
                -----BEGIN CERTIFICATE-----
                MIIIntermediate==
                -----END CERTIFICATE-----"""
        );
    }
}
