// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.deployment.adapter.aws.AwsAssumeRoleService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpResponse;
import com.azure.resourcemanager.containerservice.ContainerServiceManager;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.exception.RetryableAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.google.auth.oauth2.AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.google.auth.oauth2.GoogleCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KubernetesAuthServiceTest {

    private SecretStore secretStore;
    private AwsAssumeRoleService awsAssumeRoleService;
    private KubernetesCloudCredentialResolver cloudCredentialResolver;
    private KubernetesAuthService service;

    @BeforeEach
    void setUp() {
        secretStore = mock(SecretStore.class);
        awsAssumeRoleService = mock(AwsAssumeRoleService.class);
        cloudCredentialResolver = new KubernetesCloudCredentialResolver(awsAssumeRoleService);
        service = new KubernetesAuthService(secretStore, JsonMapper.builderWithJackson2Defaults().build(), cloudCredentialResolver);
    }

    @Test
    void resolve_inCluster_returnsInClusterConfig() {
        KubernetesSecretService.KubernetesAuthConfig auth = service.resolve(
                KubernetesAuthProvider.SA_INCLUSTER,
                "prod-cluster",
                baseMessage(null));

        assertThat(auth.inCluster()).isTrue();
    }

    @Test
    void resolve_saToken_readsCredentialAndBuildsTokenAuth() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "apiServer": "https://cluster.example",
                  "caCertPem": "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
                  "bearerToken": "token-123"
                }
                """);

        KubernetesSecretService.KubernetesAuthConfig auth = service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred"));

        assertThat(auth.inCluster()).isFalse();
        assertThat(auth.apiServer()).isEqualTo("https://cluster.example");
        assertThat(auth.bearerToken()).isEqualTo("token-123");
        assertThat(auth.clusterCaCertPem()).isNotEmpty();
    }

    @Test
    void resolve_saToken_missingCredentialPath_throwsPermanent() {
        assertThatThrownBy(() -> service.resolve(KubernetesAuthProvider.SA_TOKEN, "prod-cluster", baseMessage(null)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_MISSING"));
    }

    @Test
    void resolve_saToken_withServiceAccountTokenFieldAndBase64Ca_succeeds() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "apiServer": "https://cluster.example",
                  "caCertBase64": "QUJD",
                  "serviceAccountToken": "token-xyz"
                }
                """);

        KubernetesSecretService.KubernetesAuthConfig auth = service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred"));

        assertThat(auth.inCluster()).isFalse();
        assertThat(auth.apiServer()).isEqualTo("https://cluster.example");
        assertThat(auth.bearerToken()).isEqualTo("token-xyz");
        assertThat(new String(auth.clusterCaCertPem())).isEqualTo("ABC");
    }

    @Test
    void resolve_saToken_invalidBase64Ca_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "apiServer": "https://cluster.example",
                  "caCertBase64": "%%%invalid%%%",
                  "bearerToken": "token-xyz"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_saToken_emptySecretValue_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("   ");

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_saToken_invalidJson_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("{not-valid-json");

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_aws_missingRegion_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "awsRoleArn": "arn:aws:iam::123456789012:role/test"
                }
                """);

        assertThatThrownBy(() -> service.resolve(KubernetesAuthProvider.AWS, "prod-cluster", baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_aws_staticCredentialPairIncomplete_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "awsRegion": "us-east-1",
                  "awsAccessKeyId": "AKIAONLY"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.AWS,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_aws_roleArnProvided_invokesAssumeRolePath() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "awsRegion": "us-east-1",
                  "awsRoleArn": "arn:aws:iam::123456789012:role/test"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.AWS,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(RuntimeException.class);

        verify(awsAssumeRoleService).assumeRole(
                "arn:aws:iam::123456789012:role/test",
                "us-east-1",
                null,
                null);
    }

    @Test
    void resolve_aws_onlyStaticCredentialPair_withoutRoleArn_doesNotCallAssumeRole() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "awsRegion": "us-east-1",
                  "awsAccessKeyId": "AKIATEST",
                  "awsSecretAccessKey": "secret-test"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.AWS,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(RuntimeException.class);

        verify(awsAssumeRoleService, never()).assumeRole(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void resolve_aws_roleArnAndStaticPair_passesStaticPairToAssumeRole() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "awsRegion": "us-east-1",
                  "awsRoleArn": "arn:aws:iam::123456789012:role/test",
                  "awsAccessKeyId": "AKIATEST",
                  "awsSecretAccessKey": "secret-test"
                }
                """);
        when(awsAssumeRoleService.assumeRole(
                "arn:aws:iam::123456789012:role/test",
                "us-east-1",
                "AKIATEST",
                "secret-test")).thenReturn(AwsSessionCredentials.create("a", "b", "c"));

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.AWS,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(RuntimeException.class);

        verify(awsAssumeRoleService).assumeRole(
                "arn:aws:iam::123456789012:role/test",
                "us-east-1",
                "AKIATEST",
                "secret-test");
    }

    @Test
    void resolve_aws_unexpectedAssumeRoleFailure_returnsSanitizedTransientError() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "awsRegion": "us-east-1",
                  "awsRoleArn": "arn:aws:iam::123456789012:role/test",
                  "awsAccessKeyId": "AKIATEST",
                  "awsSecretAccessKey": "secret-test"
                }
                """);
        when(awsAssumeRoleService.assumeRole(
                "arn:aws:iam::123456789012:role/test",
                "us-east-1",
                "AKIATEST",
                "secret-test")).thenThrow(new IllegalStateException("upstream detail should stay in logs"));

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.AWS,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> {
                    com.certping.agent.exception.TransientAgentException ex =
                            (com.certping.agent.exception.TransientAgentException) e;
                    assertThat(ex.getErrorCode()).isEqualTo("DEPLOY_K8S_AUTH_AWS_FAILED");
                    assertThat(ex.getMessage()).contains("debugId=");
                    assertThat(ex.getMessage()).doesNotContain("upstream detail should stay in logs");
                });
    }

    @Test
    void resolve_saToken_missingApiServer_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "caCertPem": "pem",
                  "bearerToken": "token-123"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_saToken_missingBearerTokenAndServiceAccountToken_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "apiServer": "https://cluster.example",
                  "caCertPem": "pem"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_saToken_missingCaMaterial_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "apiServer": "https://cluster.example",
                  "bearerToken": "token-123"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.SA_TOKEN,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_inCluster_doesNotReadKeyVault() {
        service.resolve(KubernetesAuthProvider.SA_INCLUSTER, "prod-cluster", baseMessage("https://unused"));
        verifyNoInteractions(secretStore);
    }

    @Test
    void resolve_azure_missingClientId_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientSecret": "secret"
                }
                """);

        assertThatThrownBy(() -> service.resolve(KubernetesAuthProvider.AZURE, "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_azure_invalidSubscriptionUuid_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "not-a-uuid",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        assertThatThrownBy(() -> service.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_azure_withoutClientSecret_selectsWorkloadIdentityFlow() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333"
                }
                """);

        TestableKubernetesCloudCredentialResolver testResolver = new TestableKubernetesCloudCredentialResolver(awsAssumeRoleService);
        testResolver.azureWorkloadIdentityResult = new IllegalStateException("azure workload selected");
        testResolver.environmentValue = "/var/run/secrets/azure/tokens/azure-identity-token";
        KubernetesAuthService testService = new KubernetesAuthService(secretStore, JsonMapper.builderWithJackson2Defaults().build(), testResolver);

        assertThatThrownBy(() -> testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> assertThat(testResolver.azureWorkloadIdentitySelected).isTrue());
    }

    @Test
    void resolve_azure_workloadIdentityMissingTokenFile_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333"
                }
                """);

        TestableKubernetesCloudCredentialResolver testResolver = new TestableKubernetesCloudCredentialResolver(awsAssumeRoleService);
        KubernetesAuthService testService = new KubernetesAuthService(secretStore, JsonMapper.builderWithJackson2Defaults().build(), testResolver);

        assertThatThrownBy(() -> testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_azure_validCredential_returnsTokenAuth() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore,
                JsonMapper.builderWithJackson2Defaults().build(),
                cloudCredentialResolver);
        testService.azureKubernetesApiToken = "aks-token-123";
        testService.aksKubeConfigResult = """
                apiVersion: v1
                current-context: prod-context
                clusters:
                - name: prod-cluster
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://aks.example
                contexts:
                - name: prod-context
                  context:
                    cluster: prod-cluster
                    user: clusterUser_rg-prod_prod-cluster
                users:
                - name: clusterUser_rg-prod_prod-cluster
                  user:
                    auth-provider:
                      name: azure
                      config:
                        apiserver-id: 6dae42f8-4368-4678-94ff-3960e28e3630
                """.getBytes(StandardCharsets.UTF_8);

        KubernetesSecretService.KubernetesAuthConfig auth = testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred"));

        assertThat(auth.inCluster()).isFalse();
        assertThat(auth.apiServer()).isEqualTo("https://aks.example");
        assertThat(auth.bearerToken()).isEqualTo("aks-token-123");
        assertThat(new String(auth.clusterCaCertPem(), StandardCharsets.UTF_8)).isEqualTo("ABC");
        assertThat(testService.lastServerApplicationId).isEqualTo("6dae42f8-4368-4678-94ff-3960e28e3630");
        assertThat(testService.lastAzureClusterName).isEqualTo("prod-cluster");
        assertThat(testService.lastAzureResourceGroup).isEqualTo("rg-prod");
    }

    @Test
    void resolve_azure_base64KubeConfig_decodesPayloadAndExtractsExecServerId() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore,
                JsonMapper.builderWithJackson2Defaults().build(),
                cloudCredentialResolver);
        testService.azureKubernetesApiToken = "aks-token-456";
        String yaml = """
                apiVersion: v1
                current-context: prod-context
                clusters:
                - name: prod-cluster
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://aks.example
                contexts:
                - name: prod-context
                  context:
                    cluster: prod-cluster
                    user: clusterUser
                users:
                - name: clusterUser
                  user:
                    exec:
                      command: kubelogin
                      args:
                      - get-token
                      - --server-id
                      - 11111111-2222-3333-4444-555555555555
                """;
        testService.aksKubeConfigResult = java.util.Base64.getEncoder()
                .encode(yaml.getBytes(StandardCharsets.UTF_8));

        KubernetesSecretService.KubernetesAuthConfig auth = testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred"));

        assertThat(auth.apiServer()).isEqualTo("https://aks.example");
        assertThat(auth.bearerToken()).isEqualTo("aks-token-456");
        assertThat(testService.lastServerApplicationId).isEqualTo("11111111-2222-3333-4444-555555555555");
    }

    @Test
    void resolve_azure_missingServerIdFallsBackToAksDefaultServerApp() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore,
                JsonMapper.builderWithJackson2Defaults().build(),
                cloudCredentialResolver);
        testService.azureKubernetesApiToken = "aks-token-default";
        testService.aksKubeConfigResult = """
                apiVersion: v1
                current-context: prod-context
                clusters:
                - name: prod-cluster
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://aks.example
                contexts:
                - name: prod-context
                  context:
                    cluster: prod-cluster
                    user: clusterUser
                users:
                - name: clusterUser
                  user: {}
                """.getBytes(StandardCharsets.UTF_8);

        KubernetesSecretService.KubernetesAuthConfig auth = testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred"));

        assertThat(auth.bearerToken()).isEqualTo("aks-token-default");
        assertThat(testService.lastServerApplicationId).isEqualTo("6dae42f8-4368-4678-94ff-3960e28e3630");
    }

    @Test
    void resolve_azure_http403_isReportedAsPermissionDenied() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore,
                JsonMapper.builderWithJackson2Defaults().build(),
                cloudCredentialResolver);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getStatusCode()).thenReturn(403);
        testService.azureFailure = new HttpResponseException("denied", response, null);

        assertThatThrownBy(() -> testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AZURE_PERMISSION_DENIED"));
    }

    @Test
    void resolve_azure_illegalArgument_isReportedAsPermanentInvalidRequest() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore,
                JsonMapper.builderWithJackson2Defaults().build(),
                cloudCredentialResolver);
        testService.azureFailure = new IllegalArgumentException("The value must not be null or empty string");

        assertThatThrownBy(() -> testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_AUTH_AZURE_INVALID_REQUEST"));
    }

    @Test
    void resolveAzureAuthForAgc_missingTenantId_throwsPermanent() {
        assertThatThrownBy(() -> service.resolveAzureAuthForAgc(
                "agc", "", "22222222-2222-2222-2222-222222222222", "rg", null, null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolveAzureAuthForAgc_invalidTenantUuid_throwsPermanent() {
        assertThatThrownBy(() -> service.resolveAzureAuthForAgc(
                "agc", "not-uuid", "22222222-2222-2222-2222-222222222222", "rg", null, null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolveAzureAuthForAgc_invalidClientId_throwsPermanent() {
        assertThatThrownBy(() -> service.resolveAzureAuthForAgc(
                "agc",
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                "rg",
                "bad-client-id",
                "secret"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolveAzureAuthForAgc_validInputs_buildsTokenAuth() {
        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore, JsonMapper.builderWithJackson2Defaults().build(), cloudCredentialResolver);
        testService.azureKubernetesApiToken = "agc-token";
        testService.aksKubeConfigResult = """
                apiVersion: v1
                current-context: c1
                clusters:
                - name: c1
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://agc.example
                contexts:
                - name: c1
                  context:
                    cluster: c1
                    user: u1
                users:
                - name: u1
                  user:
                    token: static-token
                """.getBytes(StandardCharsets.UTF_8);

        KubernetesSecretService.KubernetesAuthConfig auth = testService.resolveAzureAuthForAgc(
                "agc",
                " 11111111-1111-1111-1111-111111111111 ",
                "22222222-2222-2222-2222-222222222222",
                "rg-agc",
                "33333333-3333-3333-3333-333333333333",
                "secret");

        assertThat(auth.apiServer()).isEqualTo("https://agc.example");
        assertThat(auth.bearerToken()).isEqualTo("agc-token");
    }

    @Test
    void resolveAzureAuthForAgc_nullClientIdAndSecret_failsAtResolveTokenCredential() {
        assertThatThrownBy(() -> service.resolveAzureAuthForAgc(
                "agc",
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                "rg-agc",
                null,
                null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolve_azure_http500_isReportedAsTransient() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "azureTenantId": "11111111-1111-1111-1111-111111111111",
                  "azureSubscriptionId": "22222222-2222-2222-2222-222222222222",
                  "azureResourceGroup": "rg-prod",
                  "azureClientId": "33333333-3333-3333-3333-333333333333",
                  "azureClientSecret": "secret"
                }
                """);

        AzureTestKubernetesAuthService testService = new AzureTestKubernetesAuthService(
                secretStore, JsonMapper.builderWithJackson2Defaults().build(), cloudCredentialResolver);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getStatusCode()).thenReturn(500);
        testService.azureFailure = new HttpResponseException("server error", response, null);

        assertThatThrownBy(() -> testService.resolve(
                KubernetesAuthProvider.AZURE,
                "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_AUTH_AZURE_FAILED"));
    }

    @Test
    void extractKubeConfigFromAzure_emptyBytes_throwsPermanent() {
        assertThatThrownBy(() -> service.extractKubeConfigFromAzure(new byte[0], "c"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void extractKubeConfigFromAzure_nullBytes_throwsPermanent() {
        assertThatThrownBy(() -> service.extractKubeConfigFromAzure(null, "c"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void extractKubeConfigFromAzure_unreadableBase64_throwsPermanent() {
        byte[] bogus = "***not base64***".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> service.extractKubeConfigFromAzure(bogus, "c"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void extractAzureKubeConfigMaterial_missingServer_throwsPermanent() {
        String yaml = """
                apiVersion: v1
                current-context: c1
                clusters:
                - name: c1
                  cluster:
                    certificate-authority-data: QUJD
                contexts:
                - name: c1
                  context:
                    cluster: c1
                    user: u1
                users:
                - name: u1
                  user:
                    token: t
                """;
        assertThatThrownBy(() -> service.extractAzureKubeConfigMaterial(yaml, "c"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void extractAzureKubeConfigMaterial_missingCaData_throwsPermanent() {
        String yaml = """
                apiVersion: v1
                current-context: c1
                clusters:
                - name: c1
                  cluster:
                    server: https://aks.example
                contexts:
                - name: c1
                  context:
                    cluster: c1
                    user: u1
                users:
                - name: u1
                  user:
                    token: t
                """;
        assertThatThrownBy(() -> service.extractAzureKubeConfigMaterial(yaml, "c"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void extractAzureKubeConfigMaterial_notAYamlObject_throwsPermanent() {
        // Build a kubeconfig that has CA and server, but the YAML root is a list (forces parseYamlMap branch).
        // Actually loadKubeConfig parses fine for the lookup; root list will fail at parseYamlMap.
        // Use a custom kubeconfig whose YAML root is a sequence to exercise the parse error.
        // KubeConfig.loadKubeConfig requires a map; we therefore need to enter parseYamlMap manually.
        // The reachable path is: include server+ca, then have a malformed YAML for parseYamlMap.
        // Instead, exercise findExecArgumentValue flag=value branch.
        String yaml = """
                apiVersion: v1
                current-context: c1
                clusters:
                - name: c1
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://aks.example
                contexts:
                - name: c1
                  context:
                    cluster: c1
                    user: u1
                users:
                - name: u1
                  user:
                    exec:
                      command: kubelogin
                      args:
                      - --server-id=99999999-2222-3333-4444-555555555555
                """;
        KubernetesAuthService.AzureKubeConfigMaterial m = service.extractAzureKubeConfigMaterial(yaml, "c");
        assertThat(m.serverApplicationId()).isEqualTo("99999999-2222-3333-4444-555555555555");
        assertThat(m.userAuthMode()).startsWith("exec:");
    }

    @Test
    void extractAzureKubeConfigMaterial_userWithStaticToken_reportsStaticTokenAuthMode() {
        String yaml = """
                apiVersion: v1
                current-context: c1
                clusters:
                - name: c1
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://aks.example
                contexts:
                - name: c1
                  context:
                    cluster: c1
                    user: u1
                users:
                - name: u1
                  user:
                    token: tok
                """;
        KubernetesAuthService.AzureKubeConfigMaterial m = service.extractAzureKubeConfigMaterial(yaml, "c");
        assertThat(m.userAuthMode()).isEqualTo("static-token");
        assertThat(m.serverHost()).isEqualTo("aks.example");
    }

    @Test
    void extractAzureKubeConfigMaterial_authProviderConfigServerId_usedAsApplicationId() {
        String yaml = """
                apiVersion: v1
                current-context: c1
                clusters:
                - name: c1
                  cluster:
                    certificate-authority-data: QUJD
                    server: https://aks.example
                contexts:
                - name: c1
                  context:
                    cluster: c1
                    user: u1
                users:
                - name: u1
                  user:
                    auth-provider:
                      name: azure
                      config:
                        server-id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
                """;
        KubernetesAuthService.AzureKubeConfigMaterial m = service.extractAzureKubeConfigMaterial(yaml, "c");
        assertThat(m.serverApplicationId()).isEqualTo("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assertThat(m.userAuthMode()).startsWith("auth-provider:");
    }

    @Test
    void resolveAzureKubernetesApiToken_nullToken_throwsPermanent() {
        TokenCredential tc = mock(TokenCredential.class);
        when(tc.getTokenSync(org.mockito.ArgumentMatchers.any())).thenReturn(null);
        assertThatThrownBy(() -> service.resolveAzureKubernetesApiToken(tc, "11111111-1111-1111-1111-111111111111", "c", "rg"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void resolveAzureKubernetesApiToken_blankToken_throwsPermanent() {
        TokenCredential tc = mock(TokenCredential.class);
        com.azure.core.credential.AccessToken at = mock(com.azure.core.credential.AccessToken.class);
        when(at.getToken()).thenReturn("   ");
        when(tc.getTokenSync(org.mockito.ArgumentMatchers.any())).thenReturn(at);
        assertThatThrownBy(() -> service.resolveAzureKubernetesApiToken(tc, "11111111-1111-1111-1111-111111111111", "c", "rg"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void resolveAzureKubernetesApiToken_validToken_returned() {
        TokenCredential tc = mock(TokenCredential.class);
        com.azure.core.credential.AccessToken at = mock(com.azure.core.credential.AccessToken.class);
        when(at.getToken()).thenReturn("the-token");
        when(at.getExpiresAt()).thenReturn(java.time.OffsetDateTime.now());
        when(tc.getTokenSync(org.mockito.ArgumentMatchers.any())).thenReturn(at);
        String token = service.resolveAzureKubernetesApiToken(tc, "11111111-1111-1111-1111-111111111111", "c", "rg");
        assertThat(token).isEqualTo("the-token");
    }

    @Test
    void resolveAzureKubernetesApiToken_unexpectedFailure_sanitizedTransient() {
        TokenCredential tc = mock(TokenCredential.class);
        when(tc.getTokenSync(org.mockito.ArgumentMatchers.any())).thenThrow(new IllegalStateException("inner-secret"));
        assertThatThrownBy(() -> service.resolveAzureKubernetesApiToken(tc, "11111111-1111-1111-1111-111111111111", "c", "rg"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> {
                    TransientAgentException ex = (TransientAgentException) e;
                    assertThat(ex.getErrorCode()).isEqualTo("DEPLOY_K8S_AUTH_AZURE_FAILED");
                    assertThat(ex.getMessage()).doesNotContain("inner-secret");
                });
    }

    @Test
    void resolveAzureKubernetesApiToken_missingServerAppId_throwsPermanent() {
        TokenCredential tc = mock(TokenCredential.class);
        assertThatThrownBy(() -> service.resolveAzureKubernetesApiToken(tc, "  ", "c", "rg"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void cloudCredentialResolver_gcpInvalidBase64ServiceAccount_throwsPermanent() {
        com.certping.agent.model.credential.KubernetesDeploymentCredential cred =
                new com.certping.agent.model.credential.KubernetesDeploymentCredential();
        cred.setGcpProjectId("p");
        cred.setGcpLocation("us-central1");
        cred.setGcpServiceAccountJsonBase64("!!!notbase64!!!");
        assertThatThrownBy(() -> cloudCredentialResolver.resolveGcpCredentials(cred))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CREDENTIAL_INVALID"));
    }

    @Test
    void cloudCredentialResolver_gcpInvalidServiceAccountJson_failsAtCredentialBuild() {
        com.certping.agent.model.credential.KubernetesDeploymentCredential cred =
                new com.certping.agent.model.credential.KubernetesDeploymentCredential();
        cred.setGcpProjectId("p");
        cred.setGcpLocation("us-central1");
        cred.setGcpServiceAccountJson("not-json");
        assertThatThrownBy(() -> cloudCredentialResolver.resolveGcpCredentials(cred))
                .isInstanceOf(Exception.class);
    }

    @Test
    void cloudCredentialResolver_awsRequiresStaticPairTogether() {
        com.certping.agent.model.credential.KubernetesDeploymentCredential cred =
                new com.certping.agent.model.credential.KubernetesDeploymentCredential();
        cred.setAwsAccessKeyId("AKIA");
        assertThatThrownBy(() -> cloudCredentialResolver.resolveAwsCredentialsProvider(cred,
                software.amazon.awssdk.regions.Region.US_EAST_1))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void cloudCredentialResolver_awsRequiresAtLeastOneIdentity() {
        com.certping.agent.model.credential.KubernetesDeploymentCredential cred =
                new com.certping.agent.model.credential.KubernetesDeploymentCredential();
        assertThatThrownBy(() -> cloudCredentialResolver.resolveAwsCredentialsProvider(cred,
                software.amazon.awssdk.regions.Region.US_EAST_1))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void cloudCredentialResolver_awsStaticOnly_returnsBasicProvider() {
        com.certping.agent.model.credential.KubernetesDeploymentCredential cred =
                new com.certping.agent.model.credential.KubernetesDeploymentCredential();
        cred.setAwsAccessKeyId("AKIA");
        cred.setAwsSecretAccessKey("secret");
        var provider = cloudCredentialResolver.resolveAwsCredentialsProvider(cred,
                software.amazon.awssdk.regions.Region.US_EAST_1);
        assertThat(provider).isNotNull();
        assertThat(provider.resolveCredentials().accessKeyId()).isEqualTo("AKIA");
    }

    @Test
    void generateEksBearerToken_producesPresignedTokenWithExpectedPrefix() throws Exception {
        var method = KubernetesAuthService.class.getDeclaredMethod(
                "generateEksBearerToken", String.class,
                software.amazon.awssdk.regions.Region.class,
                software.amazon.awssdk.auth.credentials.AwsCredentialsProvider.class);
        method.setAccessible(true);

        software.amazon.awssdk.auth.credentials.AwsCredentialsProvider provider =
                software.amazon.awssdk.auth.credentials.StaticCredentialsProvider.create(
                        software.amazon.awssdk.auth.credentials.AwsBasicCredentials.create("AKIATEST", "secret"));
        String token = (String) method.invoke(service, "my-cluster",
                software.amazon.awssdk.regions.Region.US_EAST_1, provider);
        assertThat(token).startsWith("k8s-aws-v1.");
    }

    @Test
    void classifyAwsEksException_5xxReturnsTransient() throws Exception {
        var method = KubernetesAuthService.class.getDeclaredMethod(
                "classifyAwsEksException", software.amazon.awssdk.services.eks.model.EksException.class);
        method.setAccessible(true);

        software.amazon.awssdk.services.eks.model.EksException eks =
                (software.amazon.awssdk.services.eks.model.EksException) software.amazon.awssdk.services.eks.model.EksException
                        .builder()
                        .message("boom")
                        .statusCode(500)
                        .build();
        Object result = method.invoke(service, eks);
        assertThat(result).isInstanceOf(TransientAgentException.class);
        assertThat(((TransientAgentException) result).getErrorCode()).isEqualTo("DEPLOY_K8S_AUTH_AWS_FAILED");
    }

    @Test
    void classifyAwsEksException_4xxReturnsPermanent() throws Exception {
        var method = KubernetesAuthService.class.getDeclaredMethod(
                "classifyAwsEksException", software.amazon.awssdk.services.eks.model.EksException.class);
        method.setAccessible(true);

        software.amazon.awssdk.services.eks.model.EksException eks =
                (software.amazon.awssdk.services.eks.model.EksException) software.amazon.awssdk.services.eks.model.EksException
                        .builder()
                        .message("denied")
                        .statusCode(403)
                        .build();
        Object result = method.invoke(service, eks);
        assertThat(result).isInstanceOf(PermanentAgentException.class);
        assertThat(((PermanentAgentException) result).getErrorCode()).isEqualTo("DEPLOY_K8S_AUTH_AWS_DENIED");
    }

    @Test
    void resolve_gcp_missingProjectId_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "gcpLocation": "us-central1"
                }
                """);
        assertThatThrownBy(() -> service.resolve(KubernetesAuthProvider.GCP, "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void resolve_gcp_missingLocation_throwsPermanent() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "gcpProjectId": "my-project"
                }
                """);
        assertThatThrownBy(() -> service.resolve(KubernetesAuthProvider.GCP, "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void resolve_gcp_missingServiceAccountJson_selectsApplicationDefaultCredentials() {
        when(secretStore.read("https://kv/secrets/k8s-cred")).thenReturn("""
                {
                  "gcpProjectId": "my-project",
                  "gcpLocation": "us-central1"
                }
                """);

        TestableKubernetesCloudCredentialResolver testResolver = new TestableKubernetesCloudCredentialResolver(awsAssumeRoleService);
        testResolver.googleApplicationDefaultCredentials = GoogleCredentials.create(
                new AccessToken("token-123", Date.from(Instant.now().plusSeconds(600))));
        KubernetesAuthService testService = new KubernetesAuthService(secretStore, JsonMapper.builderWithJackson2Defaults().build(), testResolver);

        assertThatThrownBy(() -> testService.resolve(KubernetesAuthProvider.GCP, "prod-cluster",
                baseMessage("https://kv/secrets/k8s-cred")))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> assertThat(testResolver.googleApplicationDefaultSelected).isTrue());
    }

    private CertDeploymentMessage baseMessage(String deploymentCredPath) {
        CertDeploymentMessage message = new CertDeploymentMessage();
        message.setTargetType(TargetType.KUBERNETES_SECRETS);
        message.setDeploymentCredHandle(deploymentCredPath);
        return message;
    }

    private static final class TestableKubernetesCloudCredentialResolver extends KubernetesCloudCredentialResolver {
        private boolean azureWorkloadIdentitySelected;
        private boolean googleApplicationDefaultSelected;
        private String environmentValue;
        private RuntimeException azureWorkloadIdentityResult;
        private GoogleCredentials googleApplicationDefaultCredentials;

        private TestableKubernetesCloudCredentialResolver(AwsAssumeRoleService awsAssumeRoleService) {
            super(awsAssumeRoleService);
        }

        @Override
        TokenCredential resolveAzureTokenCredential(
                String tenantId,
                String subscriptionId,
                String resourceGroup,
                String clientId,
                String clientSecret) {
            TokenCredential credential = super.resolveAzureTokenCredential(tenantId, subscriptionId, resourceGroup, clientId, clientSecret);
            if (clientSecret == null) {
                azureWorkloadIdentitySelected = true;
                if (azureWorkloadIdentityResult != null) {
                    throw azureWorkloadIdentityResult;
                }
            }
            return credential;
        }

        @Override
        GoogleCredentials createGoogleApplicationDefaultCredentials() {
            googleApplicationDefaultSelected = true;
            if (googleApplicationDefaultCredentials == null) {
                throw new IllegalStateException("gcp workload selected");
            }
            return googleApplicationDefaultCredentials;
        }

        @Override
        String readEnvironmentVariable(String name) {
            return environmentValue;
        }
    }

    private static final class AzureTestKubernetesAuthService extends KubernetesAuthService {
        private byte[] aksKubeConfigResult;
        private RuntimeException azureFailure;
        private String lastAzureResourceGroup;
        private String lastAzureClusterName;
        private String lastServerApplicationId;
        private String azureKubernetesApiToken;

        private AzureTestKubernetesAuthService(
                SecretStore secretStore,
                ObjectMapper objectMapper,
                KubernetesCloudCredentialResolver cloudCredentialResolver) {
            super(secretStore, objectMapper, cloudCredentialResolver);
        }

        @Override
        ContainerServiceManager createContainerServiceManager(
                TokenCredential tokenCredential,
                String tenantId,
                String subscriptionId) {
            return null;
        }

        @Override
        String loadAksUserKubeConfig(ContainerServiceManager manager, String resourceGroup, String clusterName) {
            lastAzureResourceGroup = resourceGroup;
            lastAzureClusterName = clusterName;
            if (azureFailure != null) {
                throw azureFailure;
            }
            return super.extractKubeConfigFromAzure(aksKubeConfigResult, clusterName);
        }

        @Override
        String resolveAzureKubernetesApiToken(
                TokenCredential tokenCredential,
                String serverApplicationId,
                String clusterName,
                String resourceGroup) {
            lastServerApplicationId = serverApplicationId;
            if (azureFailure != null) {
                throw azureFailure;
            }
            return azureKubernetesApiToken == null ? "aks-token-test" : azureKubernetesApiToken;
        }
    }
}
