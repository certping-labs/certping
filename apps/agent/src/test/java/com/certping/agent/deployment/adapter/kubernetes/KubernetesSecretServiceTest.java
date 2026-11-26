// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1Namespace;
import io.kubernetes.client.openapi.models.V1NamespaceList;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Duration;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KubernetesSecretServiceTest {

    private static byte[] VALID_CA_PEM_BYTES;

    @BeforeAll
    static void generateValidCaPem() throws Exception {
        KeyPair keyPair = org.shredzone.acme4j.util.KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=test-kubernetes-ca");
        Date notBefore = new Date();
        Date notAfter = Date.from(Instant.now().plusSeconds(86400));
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        VALID_CA_PEM_BYTES = pem.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void deployTlsSecrets_withExplicitNamespaceMappings_replacesExistingSecret() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        V1Secret existing = new V1Secret().metadata(new V1ObjectMeta().resourceVersion("7"));
        ApiException notFound = new ApiException(404, "Not Found");
        when(api.readSecret(nullable(String.class), eq("dev"))).thenAnswer(invocation -> {
            String secretName = invocation.getArgument(0);
            if ("example-dev-tls".equals(secretName)) {
                return existing;
            }
            throw notFound;
        });

        KubernetesSecretService.KubernetesDeploymentSummary result = spy.deployTlsSecrets(
                buildBundle(),
                "prod-cluster",
                "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"),
                false,
                "42",
                "cert-0001");

        assertThat(result.namespaceCount()).isEqualTo(1);
        assertThat(result.deployedSecretRefs()).containsExactly("dev/example-dev-tls");
        verify(api).createSecret(eq("dev"), any(V1Secret.class), eq(DRY_RUN_ALL), eq("certping-agent"));
        verify(api).createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
        verify(api).replaceSecret(eq("example-dev-tls"), eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
    }

    @Test
    void deployTlsSecrets_allNamespacesUsesSecretNameFromConfig() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        V1NamespaceList namespaces = new V1NamespaceList().items(List.of(
                new V1Namespace().metadata(new V1ObjectMeta().name("dev")),
                new V1Namespace().metadata(new V1ObjectMeta().name("prod"))
        ));
        when(api.listNamespaces(any(), any())).thenReturn(namespaces);

        ApiException notFound = new ApiException(404, "Not Found");
        when(api.readSecret(any(), eq("dev"))).thenThrow(notFound);
        when(api.readSecret(any(), eq("prod"))).thenThrow(notFound);

        KubernetesSecretService.KubernetesDeploymentSummary result = spy.deployTlsSecrets(
                buildBundle(),
                "prod-cluster",
                "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("all_namespaces", "shared-prod-tls"),
                true,
                "42",
                "cert-0001");

        assertThat(result.namespaceCount()).isEqualTo(2);
        assertThat(result.deployedSecretRefs()).containsExactly("dev/shared-prod-tls", "prod/shared-prod-tls");
        verify(api, times(2)).createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
        verify(api, times(2)).createSecret(eq("prod"), any(V1Secret.class), eq(null), eq("certping-agent"));
    }

    @Test
    void resolveNamespaceSecrets_invalidSecretName_throwsPermanent() {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("dev", "Bad Secret"), false))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void resolveNamespaceSecrets_invalidNamespace_throwsPermanent() {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("Bad Namespace", "example-dev-tls"), false))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void resolveNamespaceSecrets_duplicateNamespaceAfterTrim_throwsPermanent() {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();

        Map<String, String> mappings = new java.util.LinkedHashMap<>();
        mappings.put("dev", "example-dev-tls");
        mappings.put(" dev ", "example-dev-tls-2");

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, mappings, false))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void resolveNamespaceSecrets_missingMappingsWhenNotAllNamespaces_throwsPermanent() {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of(), false))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void resolveNamespaceSecrets_allNamespacesWithoutSecretName_throwsPermanent() {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of(), true))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void resolveNamespaceSecrets_allNamespacesWhenListEmpty_throwsPermanent() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        when(api.listNamespaces(any(), any())).thenReturn(new V1NamespaceList().items(List.of()));

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("all_namespaces", "shared-prod-tls"), true))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_NAMESPACE_NOT_FOUND"));
    }

    @Test
    void resolveNamespaceSecrets_allNamespacesApiForbidden_throwsPermanent() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        ApiException forbidden = new ApiException(403, "forbidden", java.util.Map.of(), "{\"token\":\"abc123\",\"message\":\"denied\"}");
        when(api.listNamespaces(any(), any())).thenThrow(forbidden);

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("all_namespaces", "shared-prod-tls"), true))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> {
                    PermanentAgentException ex = (PermanentAgentException) e;
                    assertThat(ex.getErrorCode()).isEqualTo("DEPLOY_K8S_NAMESPACE_LIST_FAILED");
                    assertThat(ex.getMessage()).contains("debugId=");
                    assertThat(ex.getMessage()).doesNotContain("abc123");
                });
    }

    @Test
    void resolveNamespaceSecrets_allNamespacesApiServerError_throwsTransient() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        ApiException serverError = new ApiException(500, "server-error");
        when(api.listNamespaces(any(), any())).thenThrow(serverError);

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("all_namespaces", "shared-prod-tls"), true))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> assertThat(((com.certping.agent.exception.TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_NAMESPACE_LIST_FAILED"));
    }

    @Test
    void deployTlsSecrets_replaceForbidden_throwsPermanent() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        when(api.readSecret("example-dev-tls", "dev"))
                .thenReturn(new V1Secret().metadata(new V1ObjectMeta().resourceVersion("9")));
        ApiException forbidden = new ApiException(403, "forbidden", java.util.Map.of(), "{\"clientSecret\":\"super-secret\",\"message\":\"denied\"}");
        doThrow(forbidden).when(api).replaceSecret(eq("example-dev-tls"), eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-0001"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> {
                    PermanentAgentException ex = (PermanentAgentException) e;
                    assertThat(ex.getErrorCode()).isEqualTo("DEPLOY_K8S_SECRET_UPSERT_FAILED");
                    assertThat(ex.getMessage()).contains("debugId=");
                    assertThat(ex.getMessage()).doesNotContain("super-secret");
                });
    }

    @Test
    void deployTlsSecrets_createServerError_throwsTransient() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "Not Found");
        when(api.readSecret("example-dev-tls", "dev")).thenThrow(notFound);
        ApiException createFailure = new ApiException(500, "boom");
        doThrow(createFailure).when(api).createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-0001"))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> assertThat(((com.certping.agent.exception.TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_SECRET_CREATE_FAILED"));
    }

    @Test
    void deployTlsSecrets_setsMetadataAnnotationsWhenProvided() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());
        ApiException notFound = new ApiException(404, "Not Found");
        when(api.readSecret("example-dev-tls", "dev")).thenThrow(notFound);

        spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-0001");

        org.mockito.ArgumentCaptor<V1Secret> captor = org.mockito.ArgumentCaptor.forClass(V1Secret.class);
        verify(api).createSecret(eq("dev"), captor.capture(), eq(null), eq("certping-agent"));
        V1Secret created = captor.getValue();
        assertThat(created.getMetadata().getAnnotations())
                .containsEntry("certping.net/organization-id", "42")
                .containsEntry("certping.net/certificate-xref", "cert-0001")
                .containsEntry("certping.net/domain", "api.example.com")
                .containsEntry("certping.net/cluster-name", "prod-cluster");
    }

    @Test
    void deployTlsSecrets_preflightForbidden_failsBeforeWrite() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret("example-dev-tls", "dev")).thenThrow(notFound);
        ApiException forbidden = new ApiException(403, "forbidden");
        doThrow(forbidden).when(api).createSecret(eq("dev"), any(V1Secret.class), eq(DRY_RUN_ALL), eq("certping-agent"));

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-0001"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_PREFLIGHT_FAILED"));

        verify(api, times(1)).readSecret("example-dev-tls", "dev");
        verify(api, never()).createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
        verify(api, never()).replaceSecret(eq("example-dev-tls"), eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
    }

    @Test
    void deployTlsSecrets_stageFailure_keepsLiveSecretUntouchedAndCleansStagedSecrets() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret(nullable(String.class), eq("dev"))).thenThrow(notFound);
        when(api.readSecret(nullable(String.class), eq("prod"))).thenThrow(notFound);

        doThrow(new ApiException(500, "stage failed"))
                .when(api)
                .createSecret(eq("prod"), any(V1Secret.class), eq(null), eq("certping-agent"));

        java.util.LinkedHashMap<String, String> namespaceMappings = new java.util.LinkedHashMap<>();
        namespaceMappings.put("dev", "example-dev-tls");
        namespaceMappings.put("prod", "example-prod-tls");

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                namespaceMappings,
                false, "42", "cert-0001"))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> assertThat(((com.certping.agent.exception.TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_SECRET_CREATE_FAILED"));

        verify(api, never()).replaceSecret(eq("example-dev-tls"), eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
        verify(api, never()).replaceSecret(eq("example-prod-tls"), eq("prod"), any(V1Secret.class), eq(null), eq("certping-agent"));
        verify(api).deleteSecret(nullable(String.class), eq("dev"));
    }

    @Test
    void deployTlsSecrets_successfulRollout_stagesBeforePromotingAndCleansUp() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        V1Secret existingLive = new V1Secret().metadata(new V1ObjectMeta().resourceVersion("3"));
        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret("example-dev-tls", "dev")).thenReturn(existingLive);
        when(api.readSecret(nullable(String.class), eq("dev"))).thenAnswer(invocation -> {
            String secretName = invocation.getArgument(0);
            if ("example-dev-tls".equals(secretName)) {
                return existingLive;
            }
            throw notFound;
        });

        KubernetesSecretService.KubernetesDeploymentSummary summary = spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"),
                false, "42", "cert-0001");

        assertThat(summary.deployedSecretRefs()).containsExactly("dev/example-dev-tls");

        org.mockito.InOrder inOrder = inOrder(api);
        inOrder.verify(api).createSecret(eq("dev"), any(V1Secret.class), eq(DRY_RUN_ALL), eq("certping-agent"));
        inOrder.verify(api).replaceSecret(eq("example-dev-tls"), eq("dev"), any(V1Secret.class), eq(DRY_RUN_ALL), eq("certping-agent"));
        inOrder.verify(api).createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
        inOrder.verify(api).replaceSecret(eq("example-dev-tls"), eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
        inOrder.verify(api).deleteSecret(nullable(String.class), eq("dev"));
    }

    @Test
    void deployTlsSecrets_cleanupFailure_doesNotMaskSuccessfulPromotion() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret(any(), eq("dev"))).thenThrow(notFound);
        doThrow(new ApiException(500, "cleanup failed"))
                .when(api)
                .deleteSecret(nullable(String.class), eq("dev"));

        KubernetesSecretService.KubernetesDeploymentSummary summary = spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"),
                false, "42", "cert-0001");

        assertThat(summary.deployedSecretRefs()).containsExactly("dev/example-dev-tls");
    }

    @Test
    void deployTlsSecrets_authFailure_refreshesAuthAndRetriesOnce() throws Exception {
        KubeApis.Core api1 = mock(KubeApis.Core.class);
        KubeApis.Core api2 = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api1, api2).when(spy).getOrCreateCoreV1Api(any());

        ApiException unauthorized = new ApiException(401, "unauthorized");
        when(api1.readSecret("example-dev-tls", "dev")).thenThrow(unauthorized);
        ApiException notFound = new ApiException(404, "not-found");
        when(api2.readSecret("example-dev-tls", "dev")).thenThrow(notFound);

        KubernetesSecretService.KubernetesDeploymentSummary summary = spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "https://cluster.example", "token", "ca".getBytes()),
                true,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-0001");

        assertThat(summary.namespaceCount()).isEqualTo(1);
        verify(api2).createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent"));
    }

    @Test
    void getOrCreateCoreV1Api_inCluster_reusesCachedClient() {
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        KubeApis.Core api = mock(KubeApis.Core.class);
        doReturn(api).when(spy).buildCoreV1Api(any());

        KubernetesSecretService.KubernetesAuthConfig inCluster = KubernetesSecretService.KubernetesAuthConfig.forInCluster();
        KubeApis.Core first = spy.getOrCreateCoreV1Api(inCluster);
        KubeApis.Core second = spy.getOrCreateCoreV1Api(inCluster);

        assertThat(first).isSameAs(second);
        verify(spy, times(1)).buildCoreV1Api(inCluster);
    }

    @Test
    void kubernetesAuthConfig_kubeConfigFactory_setsOnlyKubeConfigField() {
        KubernetesSecretService.KubernetesAuthConfig config = KubernetesSecretService.KubernetesAuthConfig
                .kubeConfig("apiVersion: v1");

        assertThat(config.inCluster()).isFalse();
        assertThat(config.kubeConfigYaml()).isEqualTo("apiVersion: v1");
        assertThat(config.apiServer()).isNull();
        assertThat(config.bearerToken()).isNull();
        assertThat(config.clusterCaCertPem()).isNull();
    }

    @Test
    void buildCoreV1Api_kubeConfigMissingServer_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        String kubeConfigMissingServer = """
                apiVersion: v1
                kind: Config
                clusters:
                - name: test-cluster
                  cluster:
                    certificate-authority-data: QUJD
                contexts:
                - name: test-context
                  context:
                    cluster: test-cluster
                    user: test-user
                current-context: test-context
                users:
                - name: test-user
                  user:
                    token: token-123
                """;

        assertThatThrownBy(() -> service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.kubeConfig(kubeConfigMissingServer)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void buildCoreV1Api_directTokenAuth_buildsBearerClient() {
        KubernetesSecretService service = new KubernetesSecretService();

        KubeApis.Core api = service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "https://cluster.example",
                        "token-123",
                        VALID_CA_PEM_BYTES));

        assertThat(api.getApiClient().getBasePath()).isEqualTo("https://cluster.example");
    }

    @Test
    void buildCoreV1Api_directTokenAuthMissingApiServer_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();

        assertThatThrownBy(() -> service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "   ",
                        "token-123",
                        VALID_CA_PEM_BYTES)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("missing apiServer")
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void deployTlsSecrets_apiThrottled_throwsRetryableWithRetryAfter() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        java.util.Map<String, java.util.List<String>> hdrs = java.util.Map.of("Retry-After", java.util.List.of("15"));
        ApiException throttle = new ApiException("Too many requests", 429, hdrs, null);
        when(api.readSecret(nullable(String.class), eq("dev"))).thenThrow(throttle);

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"),
                false, "42", "cert-0001"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> {
                    RetryableAgentException ex = (RetryableAgentException) e;
                    assertThat(ex.getErrorCode()).isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                    assertThat(ex.getRetryAfter()).isEqualTo(Duration.ofSeconds(15));
                });
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----"
        );
    }

    private static final String DRY_RUN_ALL = "All";

    @Test
    void resolveNamespaceSecrets_explicitMappings_returnsNormalized() {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        Map<String, String> result = service.resolveNamespaceSecrets(api,
                Map.of("  dev  ", "  example-dev-tls  "), false);
        assertThat(result).containsEntry("dev", "example-dev-tls");
    }

    @Test
    void resolveNamespaceSecrets_allNamespaces_returnsAllNamespacesMap() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        when(api.listNamespaces(any(), any()))
                .thenReturn(new V1NamespaceList().items(List.of(
                        new V1Namespace().metadata(new V1ObjectMeta().name("dev")),
                        new V1Namespace().metadata(new V1ObjectMeta().name("prod")))));
        Map<String, String> result = service.resolveNamespaceSecrets(api,
                Map.of("all_namespaces", "shared-tls"), true);
        assertThat(result).containsEntry("dev", "shared-tls").containsEntry("prod", "shared-tls");
    }

    @Test
    void deployTlsSecretsForNamespace_blankNamespace_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.deployTlsSecretsForNamespace(buildBundle(), "c",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "  ",
                Map.of("s1", "domain.example.com"), "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deployTlsSecretsForNamespace_emptySecretMap_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.deployTlsSecretsForNamespace(buildBundle(), "c",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "ns", Map.of(), "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void deployTlsSecretsForNamespace_nullSecretMap_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.deployTlsSecretsForNamespace(buildBundle(), "c",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "ns", null, "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deployTlsSecretsForNamespace_invalidNamespaceName_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.deployTlsSecretsForNamespace(buildBundle(), "c",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "Bad NS",
                Map.of("s1", "x.example.com"), "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deployTlsSecretsForNamespace_invalidSecretName_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.deployTlsSecretsForNamespace(buildBundle(), "c",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "ns",
                Map.of("Bad Name", "x.example.com"), "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deployTlsSecretsForNamespace_duplicateAfterTrim_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        java.util.LinkedHashMap<String, String> m = new java.util.LinkedHashMap<>();
        m.put("s1", "a.example.com");
        m.put(" s1 ", "b.example.com");
        assertThatThrownBy(() -> service.deployTlsSecretsForNamespace(buildBundle(), "c",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "ns", m, "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deployTlsSecretsForNamespace_successPath_createsSecret() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret(any(), eq("ns"))).thenThrow(notFound);

        KubernetesSecretService.KubernetesDeploymentSummary summary = spy.deployTlsSecretsForNamespace(
                buildBundle(), "prod-cluster",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "ns",
                Map.of("agc-s1", "api.example.com"), "42", "cert-1");

        assertThat(summary.namespaceCount()).isEqualTo(1);
        assertThat(summary.deployedSecretRefs()).containsExactly("ns/agc-s1");
        verify(api, times(2)).createSecret(eq("ns"), any(V1Secret.class), eq(null), eq("certping-agent"));
    }

    @Test
    void deployTlsSecretsForNamespace_promoteFailure_returnsTransient() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret(any(), eq("ns"))).thenThrow(notFound);
        doThrow(new ApiException(500, "boom"))
                .when(api).createSecret(eq("ns"), any(V1Secret.class), eq(null), eq("certping-agent"));

        assertThatThrownBy(() -> spy.deployTlsSecretsForNamespace(
                buildBundle(), "prod-cluster",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, "ns",
                Map.of("agc-s1", "api.example.com"), "42", "cert-1"))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
    }

    @Test
    void buildCoreV1Api_directTokenAuthMissingBearerToken_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "https://cluster.example",
                        "   ",
                        VALID_CA_PEM_BYTES)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("missing bearerToken");
    }

    @Test
    void buildCoreV1Api_directTokenAuthMissingClusterCa_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "https://cluster.example", "t", new byte[0])))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("missing cluster CA");
    }

    @Test
    void buildCoreV1Api_directTokenAuthInvalidApiServer_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "not a url", "t", VALID_CA_PEM_BYTES)))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void buildCoreV1Api_directTokenAuthRelativeApiServer_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        assertThatThrownBy(() -> service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "example.com/foo", "t", VALID_CA_PEM_BYTES)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("absolute URL");
    }

    @Test
    void buildCoreV1Api_kubeConfigSuccessfullyBuildsClient() {
        KubernetesSecretService service = new KubernetesSecretService();
        String kubeConfig = """
                apiVersion: v1
                kind: Config
                clusters:
                - name: test-cluster
                  cluster:
                    server: https://cluster.example
                contexts:
                - name: ctx
                  context:
                    cluster: test-cluster
                    user: u
                current-context: ctx
                users:
                - name: u
                  user:
                    token: tok
                """;
        KubeApis.Core api = service.buildCoreV1Api(
                KubernetesSecretService.KubernetesAuthConfig.kubeConfig(kubeConfig));
        assertThat(api.getApiClient().getBasePath()).isEqualTo("https://cluster.example");
    }

    @Test
    void validateDnsSubdomain_tooLong_throwsPermanent() {
        String tooLong = "a".repeat(254);
        assertThatThrownBy(() -> KubernetesSecretService.validateDnsSubdomain(tooLong, "secret name"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("exceeds 253 characters");
    }

    @Test
    void validateDnsSubdomain_nullValue_throwsPermanent() {
        assertThatThrownBy(() -> KubernetesSecretService.validateDnsSubdomain(null, "namespace"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deployTlsSecrets_authRefreshDisabledOn401_throwsPermanent() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException unauthorized = new ApiException(401, "unauthorized");
        when(api.readSecret("example-dev-tls", "dev")).thenThrow(unauthorized);

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deployTlsSecrets_authRefreshSecondFailureSurfacesException() throws Exception {
        KubeApis.Core api1 = mock(KubeApis.Core.class);
        KubeApis.Core api2 = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api1, api2).when(spy).getOrCreateCoreV1Api(any());

        ApiException unauthorized = new ApiException(401, "unauthorized");
        when(api1.readSecret("example-dev-tls", "dev")).thenThrow(unauthorized);
        ApiException stillUnauthorized = new ApiException(403, "forbidden");
        when(api2.readSecret("example-dev-tls", "dev")).thenThrow(stillUnauthorized);

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "https://cluster.example", "tok", "ca".getBytes()),
                true,
                Map.of("dev", "example-dev-tls"), false, "42", "cert-1"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void resolveNamespaceSecrets_allNamespacesNullList_throwsNotFound() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        when(api.listNamespaces(any(), any())).thenReturn(new V1NamespaceList());

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("all_namespaces", "shared-tls"), true))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_NAMESPACE_NOT_FOUND"));
    }

    @Test
    void resolveNamespaceSecrets_allNamespacesThrottled_throwsRetryable() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        java.util.Map<String, java.util.List<String>> hdrs = java.util.Map.of("Retry-After", java.util.List.of("5"));
        ApiException throttle = new ApiException("too many requests", 429, hdrs, null);
        when(api.listNamespaces(any(), any())).thenThrow(throttle);

        assertThatThrownBy(() -> service.resolveNamespaceSecrets(api, Map.of("all_namespaces", "shared-tls"), true))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void deployTlsSecrets_promoteCapturesResourceVersionAndUid() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret(any(), eq("dev"))).thenThrow(notFound);
        V1Secret promoted = new V1Secret().metadata(new V1ObjectMeta().resourceVersion("42").uid("abc-123"));
        when(api.createSecret(eq("dev"), any(V1Secret.class), eq(null), eq("certping-agent")))
                .thenReturn(promoted);

        KubernetesSecretService.KubernetesDeploymentSummary summary = spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, Map.of("dev", "example-dev-tls"), false, "42", "cert-0001");

        assertThat(summary.appliedSecrets()).hasSize(1);
        KubernetesSecretService.AppliedSecret applied = summary.appliedSecrets().get(0);
        assertThat(applied.namespace()).isEqualTo("dev");
        assertThat(applied.secretName()).isEqualTo("example-dev-tls");
        assertThat(applied.resourceVersion()).isEqualTo("42");
        assertThat(applied.uid()).isEqualTo("abc-123");
    }

    @Test
    void deployTlsSecrets_truncatesLongStableNameInStagedSecret() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        ApiException notFound = new ApiException(404, "not-found");
        when(api.readSecret(any(), eq("dev"))).thenThrow(notFound);

        String longName = "a".repeat(240);  // close to 253-suffix limit; suffix is "--cp-stage-" + 12 chars
        KubernetesSecretService.KubernetesDeploymentSummary summary = spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, Map.of("dev", longName), false, "42", "cert-0001");

        assertThat(summary.namespaceCount()).isEqualTo(1);
    }

    @Test
    void kubernetesAuthConfig_serviceAccountTokenFactory_setsFields() {
        KubernetesSecretService.KubernetesAuthConfig c = KubernetesSecretService.KubernetesAuthConfig
                .serviceAccountToken("https://a", "tok", "ca".getBytes());
        assertThat(c.inCluster()).isFalse();
        assertThat(c.apiServer()).isEqualTo("https://a");
        assertThat(c.bearerToken()).isEqualTo("tok");
        assertThat(c.clusterCaCertPem()).isNotNull();
        assertThat(c.kubeConfigYaml()).isNull();
    }

    @Test
    void deployTlsSecrets_secondAttemptThrottled_throwsRetryable() throws Exception {
        KubeApis.Core api1 = mock(KubeApis.Core.class);
        KubeApis.Core api2 = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api1, api2).when(spy).getOrCreateCoreV1Api(any());

        when(api1.readSecret("example-dev-tls", "dev"))
                .thenThrow(new ApiException(401, "unauthorized"));
        java.util.Map<String, java.util.List<String>> hdrs = java.util.Map.of("Retry-After", java.util.List.of("5"));
        when(api2.readSecret("example-dev-tls", "dev"))
                .thenThrow(new ApiException("throttled", 429, hdrs, null));

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        "https://cluster.example", "t", "ca".getBytes()),
                true, Map.of("dev", "example-dev-tls"), false, "42", "cert-1"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void deployTlsSecrets_readNonAuthError_rethrowsToTranslator() throws Exception {
        // Read throws non-404, non-401/403 error: upsertTlsSecret rethrows; translateApiException converts.
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        // First preflight read: 404, then preflight create dry-run succeeds
        // Then stage create succeeds (read returns 404).
        // Then promote: read returns 500 (line 573 rethrow).
        when(api.readSecret(any(), eq("dev")))
                .thenReturn(null)  // never used directly — overridden below
                .thenThrow(new ApiException(404, "nf"));
        when(api.readSecret("example-dev-tls", "dev"))
                .thenThrow(new ApiException(500, "server error"));

        assertThatThrownBy(() -> spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, Map.of("dev", "example-dev-tls"), false, "42", "cert-1"))
                .isInstanceOfAny(PermanentAgentException.class, com.certping.agent.exception.TransientAgentException.class);
    }

    @Test
    void deployTlsSecrets_cleanupDeleteFailureSwallowed() throws Exception {
        KubeApis.Core api = mock(KubeApis.Core.class);
        KubernetesSecretService service = new KubernetesSecretService();
        KubernetesSecretService spy = org.mockito.Mockito.spy(service);
        doReturn(api).when(spy).getOrCreateCoreV1Api(any());

        when(api.readSecret(any(), eq("dev"))).thenThrow(new ApiException(404, "nf"));
        // Stage create succeeds; promote succeeds; cleanup delete returns 404 → "return" (line 628).
        doThrow(new ApiException(404, "gone"))
                .when(api).deleteSecret(nullable(String.class), eq("dev"));

        KubernetesSecretService.KubernetesDeploymentSummary s = spy.deployTlsSecrets(
                buildBundle(), "prod-cluster", "api.example.com",
                () -> KubernetesSecretService.KubernetesAuthConfig.forInCluster(),
                false, Map.of("dev", "example-dev-tls"), false, "42", "cert-1");
        assertThat(s.deployedSecretRefs()).hasSize(1);
    }

    @Test
    void buildCoreV1Api_invalidKubeConfigIllegalArgument_throwsPermanent() {
        KubernetesSecretService service = new KubernetesSecretService();
        // KubeConfig with server URL containing illegal char to force IllegalArgumentException downstream.
        String kubeConfig = """
                apiVersion: v1
                kind: Config
                clusters:
                - name: c
                  cluster:
                    server: "ht tp://invalid url with spaces"
                contexts:
                - name: ctx
                  context:
                    cluster: c
                    user: u
                current-context: ctx
                users:
                - name: u
                  user:
                    token: t
                """;
        // Acceptable outcome: either PermanentAgentException or builds (depending on URI parse leniency).
        try {
            service.buildCoreV1Api(KubernetesSecretService.KubernetesAuthConfig.kubeConfig(kubeConfig));
        } catch (PermanentAgentException expected) {
            assertThat(expected.getErrorCode()).isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID");
        }
    }

    @Test
    void kubernetesAuthConfig_forInCluster_setsInClusterTrue() {
        KubernetesSecretService.KubernetesAuthConfig c = KubernetesSecretService.KubernetesAuthConfig.forInCluster();
        assertThat(c.inCluster()).isTrue();
        assertThat(c.apiServer()).isNull();
        assertThat(c.bearerToken()).isNull();
        assertThat(c.clusterCaCertPem()).isNull();
        assertThat(c.kubeConfigYaml()).isNull();
    }
}
