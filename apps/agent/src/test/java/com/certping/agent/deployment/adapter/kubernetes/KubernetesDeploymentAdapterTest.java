// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KubernetesDeploymentAdapterTest {

    @Mock private KubernetesSecretService kubernetesSecretService;
    @Mock private KubernetesAuthService kubernetesAuthService;

    private KubernetesDeploymentAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new KubernetesDeploymentAdapter(kubernetesSecretService, kubernetesAuthService, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_withExplicitNamespaceMappings_callsServiceAndReturnsTargetResourceId() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(),
                eq("prod-cluster"),
                eq("api.example.com"),
                any(),
                eq(false),
                eq(java.util.Map.of("dev", "example-dev-tls", "prod", "example-prod-tls")),
                eq(false),
                eq("42"),
                eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        2, List.of("dev/example-dev-tls", "prod/example-prod-tls"), List.of()));
        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage("""
                {
                  "authProvider": "SA_INCLUSTER",
                  "clusterName": "prod-cluster",
                  "nsMaps": [
                    { "dev": "example-dev-tls" },
                    { "prod": "example-prod-tls" }
                  ]
                }
                """));

        assertThat(result.targetResourceId()).isEqualTo("k8s://prod-cluster/tls-secrets/2");
        assertThat(result.configJson()).isNull();
        verify(kubernetesSecretService).deployTlsSecrets(
                any(),
                eq("prod-cluster"),
                eq("api.example.com"),
                any(),
                eq(false),
                eq(java.util.Map.of("dev", "example-dev-tls", "prod", "example-prod-tls")),
                eq(false),
                eq("42"),
                eq("cert-0001"));
    }

    @Test
    void deploy_withAllNamespacesMode_delegatesAllNamespacesFlag() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(),
                eq("prod-cluster"),
                eq("api.example.com"),
                any(),
                eq(false),
                eq(java.util.Map.of("all_namespaces", "shared-prod-tls")),
                eq(true),
                eq("42"),
                eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        3, List.of("a/shared-prod-tls"), List.of()));
        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "prod-cluster", "nsMaps": { "all_namespaces": "shared-prod-tls" } }
                """));

        assertThat(result.targetResourceId()).isEqualTo("k8s://prod-cluster/tls-secrets/3");
    }

    @Test
    void deploy_missingConfigJson_throwsPermanent() {
        CertDeploymentMessage message = buildMessage(null);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), message))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_MISSING"));
    }

    @Test
    void deploy_missingClusterName_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("{\"authProvider\":\"SA_INCLUSTER\",\"nsMaps\":{\"all_namespaces\":\"shared-prod-tls\"}}")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_missingNsMaps_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "prod-cluster" }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_duplicateNamespaceMappings_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                {
                  "authProvider": "SA_INCLUSTER",
                  "clusterName": "prod-cluster",
                  "nsMaps": [
                    { "dev": "example-dev-tls" },
                    { "dev": "example-dev-tls-2" }
                  ]
                }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_missingAuthProvider_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                { "clusterName": "prod-cluster", "nsMaps": { "all_namespaces": "shared-prod-tls" } }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_allNamespacesStringMode_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "prod-cluster", "nsMaps": "all_namespaces" }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_allNamespacesMixedWithExplicitMappings_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                {
                  "authProvider": "SA_INCLUSTER",
                  "clusterName": "prod-cluster",
                  "nsMaps": { "all_namespaces": "shared-prod-tls", "dev": "example-dev-tls" }
                }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_allNamespacesInArrayForm_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                {
                  "authProvider": "SA_INCLUSTER",
                  "clusterName": "prod-cluster",
                  "nsMaps": [ { "all_namespaces": "shared-prod-tls" } ]
                }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    private CertDeploymentMessage buildMessage(String configJson) {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-123");
        msg.setCorrelationId("corr-123");
        msg.setOrganizationId("42");
        msg.setCertificateXref("cert-0001");
        msg.setDomain("api.example.com");
        msg.setCertSecretHandle("https://client-kv.vault.azure.net/secrets/cert-cert-0001");
        msg.setTargetType(TargetType.KUBERNETES_SECRETS);
        msg.setDeploymentCredHandle(null);
        msg.setRequestedAt("2026-04-29T12:34:56Z");
        msg.setConfigJson(configJson);
        return msg;
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----"
        );
    }

    @Test
    void deploy_nonStringConfigValue_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": 123, "nsMaps": { "all_namespaces": "shared-tls" } }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_malformedConfigJson_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("{not-json")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_nsMapsArrayWithMultiEntryObject_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                {
                  "authProvider": "SA_INCLUSTER",
                  "clusterName": "prod-cluster",
                  "nsMaps": [ { "a": "s1", "b": "s2" } ]
                }
                """)))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deploy_nsMapsArrayWithNonObjectEntry_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                {
                  "authProvider": "SA_INCLUSTER",
                  "clusterName": "prod-cluster",
                  "nsMaps": [ "not-an-object" ]
                }
                """)))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deploy_nsMapsAsNumber_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "prod-cluster", "nsMaps": 42 }
                """)))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deploy_nsMapsObjectForm_normalizesToServiceCall() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(), eq("prod-cluster"), eq("api.example.com"), any(),
                eq(false), eq(java.util.Map.of("ns1", "s1", "ns2", "s2")),
                eq(false), eq("42"), eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(
                        2, List.of("ns1/s1", "ns2/s2"), List.of()));
        DeploymentResult r = adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "prod-cluster",
                  "nsMaps": { "ns1": "s1", "ns2": "s2" } }
                """));
        assertThat(r.targetResourceId()).isEqualTo("k8s://prod-cluster/tls-secrets/2");
    }

    @Test
    void deploy_blankClusterName_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "  ",
                  "nsMaps": { "all_namespaces": "shared-tls" } }
                """)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deploy_emptyConfigJson_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage("   ")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_MISSING"));
    }

    @Test
    void deploy_awsAuthProvider_supportsAuthRefresh() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(), eq("prod-cluster"), eq("api.example.com"), any(),
                eq(true), eq(java.util.Map.of("all_namespaces", "shared")),
                eq(true), eq("42"), eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(1, List.of(), List.of()));
        DeploymentResult r = adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "AWS", "clusterName": "prod-cluster",
                  "nsMaps": { "all_namespaces": "shared" } }
                """));
        assertThat(r.targetResourceId()).isEqualTo("k8s://prod-cluster/tls-secrets/1");
    }

    @Test
    void deploy_gcpAuthProvider_supportsAuthRefresh() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(), eq("prod-cluster"), eq("api.example.com"), any(),
                eq(true), any(), eq(true), eq("42"), eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(1, List.of(), List.of()));
        DeploymentResult r = adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "GCP", "clusterName": "prod-cluster",
                  "nsMaps": { "all_namespaces": "shared" } }
                """));
        assertThat(r.targetResourceId()).contains("prod-cluster");
    }

    @Test
    void deploy_azureAuthProvider_supportsAuthRefresh() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(), eq("prod-cluster"), eq("api.example.com"), any(),
                eq(true), any(), eq(true), eq("42"), eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(1, List.of(), List.of()));
        DeploymentResult r = adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "AZURE", "clusterName": "prod-cluster",
                  "nsMaps": { "all_namespaces": "shared" } }
                """));
        assertThat(r.targetResourceId()).contains("prod-cluster");
    }

    @Test
    void deploy_saTokenAuthProvider_supportsAuthRefresh() {
        when(kubernetesSecretService.deployTlsSecrets(
                any(), eq("prod-cluster"), eq("api.example.com"), any(),
                eq(true), any(), eq(true), eq("42"), eq("cert-0001")))
                .thenReturn(new KubernetesSecretService.KubernetesDeploymentSummary(1, List.of(), List.of()));
        DeploymentResult r = adapter.deploy(buildBundle(), buildMessage("""
                { "authProvider": "SA_TOKEN", "clusterName": "prod-cluster",
                  "nsMaps": { "all_namespaces": "shared" } }
                """));
        assertThat(r.targetResourceId()).contains("prod-cluster");
    }

    @Test
    void deploy_missingDomainAndUnparsableCert_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage("""
                { "authProvider": "SA_INCLUSTER", "clusterName": "prod-cluster",
                  "nsMaps": { "all_namespaces": "shared" } }
                """);
        msg.setDomain(null);
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_DOMAIN_REQUIRED"));
    }
}
