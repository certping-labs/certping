// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.resourcemanager.containerservice.ContainerServiceManager;
import com.azure.resourcemanager.containerservice.models.Format;
import com.azure.resourcemanager.containerservice.models.KubernetesCluster;
import com.certping.agent.deployment.adapter.azure.AzureErrorClassifier;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.credential.KubernetesDeploymentCredential;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.AccessToken;
import com.google.cloud.container.v1.ClusterManagerClient;
import com.google.cloud.container.v1.ClusterManagerSettings;
import com.google.container.v1.Cluster;
import com.google.container.v1.GetClusterRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4PresignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.eks.EksClient;
import software.amazon.awssdk.services.eks.model.DescribeClusterResponse;
import software.amazon.awssdk.services.eks.model.EksException;
import software.amazon.awssdk.services.eks.model.ResourceNotFoundException;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.StringReader;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Converts provider-specific deployment credentials into a Kubernetes client
 * auth shape.
 *
 * <p>
 * Keeping cloud-auth logic here isolates short-lived token concerns from
 * deployment logic and
 * gives us one place to enforce strict credential validation across providers.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class KubernetesAuthService {

    private static final String EKS_TOKEN_PREFIX = "k8s-aws-v1.";
    private static final String GCP_SCOPE_CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform";
    private static final String AKS_SERVER_APP_ID = "6dae42f8-4368-4678-94ff-3960e28e3630";

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final KubernetesCloudCredentialResolver cloudCredentialResolver;

    KubernetesSecretService.KubernetesAuthConfig resolve(
            KubernetesAuthProvider provider,
            String clusterName,
            CertDeploymentMessage message) {

        String providerName = provider.name();
        return switch (provider) {
            case SA_INCLUSTER -> KubernetesSecretService.KubernetesAuthConfig.forInCluster();
            case SA_TOKEN -> resolveServiceAccountTokenAuth(readCredentialRequired(message.getDeploymentCredHandle(), providerName));
            case AWS -> resolveAwsAuth(clusterName, readCredentialRequired(message.getDeploymentCredHandle(), providerName));
            case AZURE -> resolveAzureAuth(clusterName, readCredentialRequired(message.getDeploymentCredHandle(), providerName));
            case GCP -> resolveGcpAuth(clusterName, readCredentialRequired(message.getDeploymentCredHandle(), providerName));
        };
    }

    public KubernetesSecretService.KubernetesAuthConfig resolveForDiscovery(
            KubernetesAuthProvider provider,
            String clusterName,
            String deploymentCredHandle) {
        String providerName = provider.name();
        return switch (provider) {
            case SA_INCLUSTER -> KubernetesSecretService.KubernetesAuthConfig.forInCluster();
            case SA_TOKEN -> resolveServiceAccountTokenAuth(readCredentialRequired(deploymentCredHandle, providerName));
            case AWS -> resolveAwsAuth(clusterName, readCredentialRequired(deploymentCredHandle, providerName));
            case AZURE -> resolveAzureAuth(clusterName, readCredentialRequired(deploymentCredHandle, providerName));
            case GCP -> resolveGcpAuth(clusterName, readCredentialRequired(deploymentCredHandle, providerName));
        };
    }

    public KubernetesSecretService.KubernetesAuthConfig resolveAzureAuthForAgc(
            String clusterName,
            String tenantId,
            String subscriptionId,
            String resourceGroup,
            String clientId,
            String clientSecret) {
        String requiredTenantId = requireNonBlank(tenantId, "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE credential is missing tenantId").trim();
        String requiredSubscriptionId = requireNonBlank(subscriptionId, "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE credential is missing subscriptionId").trim();
        String requiredResourceGroup = requireNonBlank(resourceGroup, "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE credential is missing resourceGroup").trim();

        String trimmedClientId = trimToNull(clientId);
        String trimmedClientSecret = trimToNull(clientSecret);

        requireUuid("tenantId", requiredTenantId);
        requireUuid("subscriptionId", requiredSubscriptionId);
        if (trimmedClientId != null) {
            requireUuid("clientId", trimmedClientId);
        }

        return resolveAzureAuthInternal(
                clusterName,
                requiredTenantId,
                requiredSubscriptionId,
                requiredResourceGroup,
                trimmedClientId,
                trimmedClientSecret,
                "AGC");
    }

    private KubernetesSecretService.KubernetesAuthConfig resolveServiceAccountTokenAuth(KubernetesDeploymentCredential credential) {
        String apiServer = requireNonBlank(credential.getApiServer(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes SA_TOKEN credential is missing apiServer");
        String bearerToken = firstNonBlank(credential.getBearerToken(), credential.getServiceAccountToken());
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes SA_TOKEN credential is missing bearerToken");
        }

        byte[] caBytes = resolveCaBytes(credential);
        return KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                apiServer.trim(),
                bearerToken.trim(),
                caBytes);
    }

    private KubernetesSecretService.KubernetesAuthConfig resolveAwsAuth(String clusterName,
            KubernetesDeploymentCredential credential) {
        String awsRegionRaw = requireNonBlank(credential.getAwsRegion(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AWS credential is missing awsRegion");

        Region region = Region.of(awsRegionRaw.trim());

        try {
            AwsCredentialsProvider credentialsProvider = cloudCredentialResolver
                    .resolveAwsCredentialsProvider(credential, region);
            try (EksClient eksClient = EksClient.builder()
                    .region(region)
                    .credentialsProvider(credentialsProvider)
                    .build()) {

                DescribeClusterResponse response = eksClient.describeCluster(r -> r.name(clusterName));
                software.amazon.awssdk.services.eks.model.Cluster cluster = response.cluster();
                if (cluster == null) {
                    throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                            "EKS DescribeCluster returned no cluster details for clusterName=" + clusterName);
                }

                String apiServer = requireNonBlank(cluster.endpoint(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                        "EKS cluster endpoint is missing for clusterName=" + clusterName);
                String caData = cluster.certificateAuthority() != null ? cluster.certificateAuthority().data() : null;
                byte[] caBytes = decodeRequiredBase64(caData,
                        "DEPLOY_K8S_CREDENTIAL_INVALID",
                        "EKS cluster certificate authority data is missing or invalid for clusterName=" + clusterName);
                String token = generateEksBearerToken(clusterName, region, credentialsProvider);

                return KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(apiServer, token, caBytes);
            }

        } catch (PermanentAgentException e) {
            throw e;
        } catch (ResourceNotFoundException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CLUSTER_NOT_FOUND",
                    "EKS cluster not found for clusterName=" + clusterName, e);
        } catch (EksException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw classifyAwsEksException(e);
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw sanitizeUnexpectedAuthFailure("DEPLOY_K8S_AUTH_AWS_FAILED",
                    "EKS authentication",
                    clusterName,
                    e);
        }
    }

    private KubernetesSecretService.KubernetesAuthConfig resolveAzureAuth(String clusterName,
            KubernetesDeploymentCredential credential) {
        String tenantId = requireNonBlank(credential.getAzureTenantId(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE credential is missing azureTenantId").trim();
        String subscriptionId = requireNonBlank(credential.getAzureSubscriptionId(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE credential is missing azureSubscriptionId").trim();
        String resourceGroup = requireNonBlank(credential.getAzureResourceGroup(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE credential is missing azureResourceGroup").trim();
        String clientId = trimToNull(credential.getAzureClientId());
        String clientSecret = trimToNull(credential.getAzureClientSecret());

        requireUuid("azureTenantId", tenantId);
        requireUuid("azureSubscriptionId", subscriptionId);
        if (clientId != null) {
            requireUuid("azureClientId", clientId);
        }

        return resolveAzureAuthInternal(
            clusterName,
            tenantId,
            subscriptionId,
            resourceGroup,
            clientId,
            clientSecret,
            "Kubernetes");
    }

    private KubernetesSecretService.KubernetesAuthConfig resolveAzureAuthInternal(
            String clusterName,
            String tenantId,
            String subscriptionId,
            String resourceGroup,
            String clientId,
            String clientSecret,
            String logContext) {
        try {
            var tokenCredential = cloudCredentialResolver.resolveAzureTokenCredential(
                tenantId,
                subscriptionId,
                resourceGroup,
                clientId,
                clientSecret);

            ContainerServiceManager manager = createContainerServiceManager(tokenCredential, tenantId, subscriptionId);
            String kubeConfigYaml = loadAksUserKubeConfig(manager, resourceGroup, clusterName);
            // AKS user kubeconfigs on modern Entra-integrated clusters often describe Azure auth through
            // auth-provider/exec blocks meant for kubelogin or client-go helpers. The Java client's legacy
            // kubeconfig auth path is much stricter there, so we only trust the kubeconfig for server/CA metadata
            // and mint the Kubernetes API bearer token directly from the Azure credential we already resolved.
            AzureKubeConfigMaterial kubeConfigMaterial = extractAzureKubeConfigMaterial(kubeConfigYaml, clusterName);
            String bearerToken = resolveAzureKubernetesApiToken(
                tokenCredential,
                kubeConfigMaterial.serverApplicationId(),
                clusterName,
                resourceGroup);

            log.info(
                "AKS kubeconfig resolved for {} clusterName={} resourceGroup={} serverHost={} authMode={} currentContext={} serverAppId={}",
                logContext,
                clusterName,
                resourceGroup,
                kubeConfigMaterial.serverHost(),
                kubeConfigMaterial.userAuthMode(),
                kubeConfigMaterial.currentContextName(),
                kubeConfigMaterial.serverApplicationId());

            return KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                kubeConfigMaterial.apiServer(),
                bearerToken,
                kubeConfigMaterial.clusterCaBytes());

        } catch (PermanentAgentException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_AUTH_AZURE_INVALID_REQUEST",
                "AKS credential lookup request is invalid for clusterName=" + clusterName + ": " + e.getMessage(), e);
        } catch (HttpResponseException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw classifyAzureException(e, clusterName);
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw sanitizeUnexpectedAuthFailure("DEPLOY_K8S_AUTH_AZURE_FAILED",
                "AKS authentication",
                clusterName,
                e);
        }
        }

    String resolveAzureKubernetesApiToken(
            TokenCredential tokenCredential,
            String serverApplicationId,
            String clusterName,
            String resourceGroup) {
        String scope = requireNonBlank(serverApplicationId, "DEPLOY_K8S_CREDENTIAL_INVALID",
                "AKS server application id is missing for clusterName=" + clusterName).trim() + "/.default";
        try {
            com.azure.core.credential.AccessToken token = tokenCredential
                    .getTokenSync(new TokenRequestContext().addScopes(scope));
            if (token == null || token.getToken() == null || token.getToken().isBlank()) {
                throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                        "Azure credential did not produce an AKS API token for clusterName=" + clusterName);
            }

            log.debug("AKS API token acquired for clusterName={} resourceGroup={} expiresAt={}",
                    clusterName,
                    resourceGroup,
                    token.getExpiresAt());
            return token.getToken();
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw sanitizeUnexpectedAuthFailure("DEPLOY_K8S_AUTH_AZURE_FAILED",
                    "AKS Kubernetes API token acquisition",
                    clusterName,
                    e);
        }
    }

    ContainerServiceManager createContainerServiceManager(
            TokenCredential tokenCredential,
            String tenantId,
            String subscriptionId) {
        AzureProfile profile = new AzureProfile(tenantId, subscriptionId, AzureEnvironment.AZURE);
        return ContainerServiceManager.authenticate(tokenCredential, profile);
    }

    private KubernetesSecretService.KubernetesAuthConfig resolveGcpAuth(String clusterName,
            KubernetesDeploymentCredential credential) {
        String projectId = requireNonBlank(credential.getGcpProjectId(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes GCP credential is missing gcpProjectId").trim();
        String location = requireNonBlank(credential.getGcpLocation(), "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes GCP credential is missing gcpLocation").trim();

        try {
            var googleCredentials = cloudCredentialResolver.resolveGcpCredentials(credential)
                    .createScoped(List.of(GCP_SCOPE_CLOUD_PLATFORM));

            AccessToken accessToken = googleCredentials.refreshAccessToken();
            if (accessToken == null || accessToken.getTokenValue() == null || accessToken.getTokenValue().isBlank()) {
                throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                        "GCP credential did not produce an access token");
            }

            ClusterManagerSettings settings = ClusterManagerSettings.newBuilder()
                    .setCredentialsProvider(FixedCredentialsProvider.create(googleCredentials))
                    .build();

            String clusterResourceName = "projects/%s/locations/%s/clusters/%s".formatted(projectId, location,
                    clusterName);
            try (ClusterManagerClient clusterManagerClient = ClusterManagerClient.create(settings)) {
                Cluster cluster = clusterManagerClient.getCluster(GetClusterRequest.newBuilder()
                        .setName(clusterResourceName)
                        .build());

                String endpoint = requireNonBlank(cluster.getEndpoint(), "DEPLOY_K8S_CLUSTER_NOT_FOUND",
                        "GKE cluster endpoint is missing for clusterName=" + clusterName);
                String apiServer = endpoint.startsWith("https://") ? endpoint : "https://" + endpoint;

                String caData = cluster.hasMasterAuth() ? cluster.getMasterAuth().getClusterCaCertificate() : null;
                byte[] caBytes = decodeRequiredBase64(caData,
                        "DEPLOY_K8S_CREDENTIAL_INVALID",
                        "GKE cluster certificate authority data is missing or invalid for clusterName=" + clusterName);

                return KubernetesSecretService.KubernetesAuthConfig.serviceAccountToken(
                        apiServer,
                        accessToken.getTokenValue(),
                        caBytes);
            }
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw sanitizeUnexpectedAuthFailure("DEPLOY_K8S_AUTH_GCP_FAILED",
                    "GKE authentication",
                    clusterName,
                    e);
        }
    }

    /**
     * `deploymentCredHandle` stays mandatory for cloud-backed providers because it
     * carries the non-secret routing
     * metadata needed to find the cluster (region, subscription/resource group,
     * project/location). The auth source
     * inside that payload is flexible: explicit secret material takes priority,
     * otherwise we fall back to provider-
     * native workload identity configured on the running pod.
     */
    private KubernetesDeploymentCredential readCredentialRequired(String credentialPath, String providerName) {
        if (credentialPath == null || credentialPath.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_MISSING",
                    "Kubernetes deployment requires deploymentCredHandle for authProvider=" + providerName);
        }

        String raw = secretStore.read(credentialPath);
        if (raw == null || raw.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes deployment credential at deploymentCredHandle is empty");
        }

        try {
            return objectMapper.readValue(raw, KubernetesDeploymentCredential.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes deployment credential payload is not valid JSON", e);
        }
    }

    /**
     * EKS bearer tokens are URL-safe base64 encodings of a pre-signed STS
     * GetCallerIdentity request.
     * The `x-k8s-aws-id` header binds that token to one cluster and prevents replay
     * across clusters.
     *
     * <p>
     * Reference for the token shape: aws-iam-authenticator project and AWS SDK
     * presigner notes.
     * https://github.com/kubernetes-sigs/aws-iam-authenticator
     * https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/STS/Presigner.html
     */
    private String generateEksBearerToken(String clusterName, Region region,
            AwsCredentialsProvider credentialsProvider) {
        AwsCredentials credentials = credentialsProvider.resolveCredentials();
        Instant now = Instant.now();

        SdkHttpFullRequest unsigned = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.GET)
                .protocol("https")
                .host("sts." + region.id() + ".amazonaws.com")
                .encodedPath("/")
                .appendHeader("x-k8s-aws-id", clusterName)
                .putRawQueryParameter("Action", "GetCallerIdentity")
                .putRawQueryParameter("Version", "2011-06-15")
                .build();

        Aws4PresignerParams presignerParams = Aws4PresignerParams.builder()
                .signingName("sts")
                .signingRegion(region)
                .awsCredentials(credentials)
                .signingClockOverride(java.time.Clock.fixed(now, java.time.ZoneOffset.UTC))
                .expirationTime(now.plusSeconds(900))
                .build();

        SdkHttpFullRequest presigned = Aws4Signer.create().presign(unsigned, presignerParams);
        URI presignedUri = presigned.getUri();
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(presignedUri.toString().getBytes(StandardCharsets.UTF_8));
        return EKS_TOKEN_PREFIX + encoded;
    }

    /**
     * We deliberately use the fluent cluster API instead of the generated ARM client.
     *
     * <p>The fluent abstraction already knows how this SDK version expects AKS user-kubeconfig requests to be shaped.
     * That keeps us off the fragile `serverFqdn` parameter path that caused runtime failures across cluster variants.
     */
    String loadAksUserKubeConfig(ContainerServiceManager manager, String resourceGroup, String clusterName) {
        try {
            KubernetesCluster cluster = manager.kubernetesClusters().getByResourceGroup(resourceGroup, clusterName);
            if (cluster == null) {
                throw new PermanentAgentException("DEPLOY_K8S_CLUSTER_NOT_FOUND",
                        "AKS cluster not found for clusterName=" + clusterName);
            }

            return extractKubeConfigFromAzure(cluster.userKubeConfigContent(Format.AZURE), clusterName);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (HttpResponseException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw classifyAzureException(e, clusterName);
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", clusterName, e);
            }
            throw sanitizeUnexpectedAuthFailure("DEPLOY_K8S_AUTH_AZURE_FAILED",
                    "AKS user kubeconfig lookup",
                    clusterName,
                    e);
        }
    }

    String extractKubeConfigFromAzure(byte[] rawValue, String clusterName) {
        if (rawValue == null || rawValue.length == 0) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "AKS returned empty kubeconfig content for clusterName=" + clusterName);
        }

        String asText = new String(rawValue, StandardCharsets.UTF_8);
        if (asText.contains("apiVersion") && asText.contains("clusters:")) {
            return asText;
        }

        try {
            return new String(Base64.getDecoder().decode(asText.trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "AKS kubeconfig payload is not readable for clusterName=" + clusterName, e);
        }
    }

    AzureKubeConfigMaterial extractAzureKubeConfigMaterial(String kubeConfigYaml, String clusterName) {
        io.kubernetes.client.util.KubeConfig kubeConfig = io.kubernetes.client.util.KubeConfig
                .loadKubeConfig(new StringReader(kubeConfigYaml));

        String apiServer = requireNonBlank(trimToNull(kubeConfig.getServer()),
                "DEPLOY_K8S_CREDENTIAL_INVALID",
                "AKS kubeconfig is missing current cluster server endpoint for clusterName=" + clusterName).trim();
        byte[] clusterCaBytes;
        try {
            clusterCaBytes = kubeConfig.getDataOrFileRelative(
                    kubeConfig.getCertificateAuthorityData(),
                    kubeConfig.getCertificateAuthorityFile());
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "AKS kubeconfig certificate authority data is unreadable for clusterName=" + clusterName, e);
        }
        if (clusterCaBytes == null || clusterCaBytes.length == 0) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "AKS kubeconfig is missing cluster certificate authority data for clusterName=" + clusterName);
        }

        Map<String, Object> root = parseYamlMap(kubeConfigYaml, clusterName);
        String currentContextName = trimToNull(stringValue(root.get("current-context")));
        Map<String, Object> currentContext = findNamedSection(root.get("contexts"), currentContextName, "context");
        String currentUserName = currentContext == null ? null : trimToNull(stringValue(currentContext.get("user")));
        Map<String, Object> currentUser = findNamedSection(root.get("users"), currentUserName, "user");
        Map<String, Object> authProvider = nestedMap(currentUser, "auth-provider");
        Map<String, Object> authProviderConfig = nestedMap(authProvider, "config");
        Map<String, Object> execSection = nestedMap(currentUser, "exec");

        String serverApplicationId = firstNonBlank(
                trimToNull(stringValue(mapValue(authProviderConfig, "apiserver-id"))),
                trimToNull(stringValue(mapValue(authProviderConfig, "server-id"))),
                findExecArgumentValue(execSection, "--server-id"),
                AKS_SERVER_APP_ID);
        String serverHost = safeHost(apiServer);
        String userAuthMode = currentUser == null
                ? "unknown"
                : authProvider != null ? "auth-provider:" + trimToNull(stringValue(authProvider.get("name")))
                : execSection != null ? "exec:" + trimToNull(stringValue(execSection.get("command")))
                : currentUser.containsKey("token") ? "static-token"
                : "unknown";

        log.debug(
                "AKS kubeconfig inspection clusterName={} currentContext={} currentUser={} userAuthMode={} hasAuthProvider={} hasExec={} hasCaData={}",
                clusterName,
                currentContextName,
                currentUserName,
                userAuthMode,
                authProvider != null,
                execSection != null,
                clusterCaBytes.length > 0);

        return new AzureKubeConfigMaterial(
                apiServer,
                clusterCaBytes,
                serverApplicationId,
                currentContextName == null ? "<unset>" : currentContextName,
                userAuthMode,
                serverHost);
    }

    private byte[] resolveCaBytes(KubernetesDeploymentCredential credential) {
        if (credential.getCaCertPem() != null && !credential.getCaCertPem().isBlank()) {
            return credential.getCaCertPem().getBytes(StandardCharsets.UTF_8);
        }

        if (credential.getCaCertBase64() != null && !credential.getCaCertBase64().isBlank()) {
            return decodeRequiredBase64(
                    credential.getCaCertBase64().trim(),
                    "DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes credential caCertBase64 is not valid Base64");
        }

        throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes credential must provide caCertPem or caCertBase64");
    }

    private byte[] decodeRequiredBase64(String value, String code, String message) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException(code, message);
        }
        try {
            return Base64.getDecoder().decode(value.trim());
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException(code, message, e);
        }
    }

    private RuntimeException classifyAwsEksException(EksException e) {
        int statusCode = e.statusCode();
        if (statusCode == 400 || statusCode == 401 || statusCode == 403 || statusCode == 404) {
            return new PermanentAgentException("DEPLOY_K8S_AUTH_AWS_DENIED",
                    "EKS authentication/authorization failed (HTTP " + statusCode + ")", e);
        }
        return new TransientAgentException("DEPLOY_K8S_AUTH_AWS_FAILED",
                "EKS request failed (HTTP " + statusCode + ")", e);
    }

    private RuntimeException classifyAzureException(HttpResponseException e, String clusterName) {
        int statusCode = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
        if (AzureErrorClassifier.isPermissionDenied(e)) {
            return new PermanentAgentException(AzureErrorClassifier.PERMISSION_DENIED,
                    "AKS credential lookup denied for clusterName=" + clusterName + " (HTTP " + statusCode + ")", e);
        }
        if (statusCode == 400 || statusCode == 401 || statusCode == 404) {
            return new PermanentAgentException("DEPLOY_K8S_AUTH_AZURE_DENIED",
                    "AKS credential lookup failed for clusterName=" + clusterName + " (HTTP " + statusCode + ")", e);
        }
        return new TransientAgentException("DEPLOY_K8S_AUTH_AZURE_FAILED",
                "AKS credential lookup failed for clusterName=" + clusterName + " (HTTP " + statusCode + ")", e);
    }

    private TransientAgentException sanitizeUnexpectedAuthFailure(
            String errorCode,
            String operation,
            String clusterName,
            Exception e) {
        String debugId = UUID.randomUUID().toString();
        String exceptionType = e.getClass().getSimpleName();
        String detail = trimToNull(e.getMessage());
        String rawMessage = detail == null ? exceptionType : exceptionType + ": " + detail;
        String logMessage = KubernetesErrorSanitizer.redactAndBound(rawMessage);

        // Upstream SDK errors can echo HTTP bodies or provider internals. We keep those
        // details in local logs
        // behind a debug id and return a stable message to the server.
        log.error(
                "[K8S-AUTH][{}] {} failed for clusterName={}: {}",
                debugId,
                operation,
                clusterName,
                logMessage,
                e);

        return new TransientAgentException(
                errorCode,
                operation + " failed for clusterName=" + clusterName + " (debugId=" + debugId + ")",
                e);
    }

    private void requireUuid(String fieldName, String value) {
        try {
            UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes credential field '" + fieldName + "' must be a valid UUID", e);
        }
    }

    private String requireNonBlank(String value, String code, String message) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException(code, message);
        }
        return value;
    }

    private String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        if (second != null && !second.isBlank()) {
            return second;
        }
        return null;
    }

    private String firstNonBlank(String first, String second, String third, String fourth) {
        String firstResolved = firstNonBlank(first, second);
        if (firstResolved != null) {
            return firstResolved;
        }
        String secondResolved = firstNonBlank(third, fourth);
        if (secondResolved != null) {
            return secondResolved;
        }
        return null;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private Map<String, Object> parseYamlMap(String yaml, String clusterName) {
        Object raw = new Yaml(new SafeConstructor(new LoaderOptions())).load(yaml);
        if (!(raw instanceof Map<?, ?> rawMap)) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "AKS kubeconfig is not a YAML object for clusterName=" + clusterName);
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        rawMap.forEach((key, value) -> normalized.put(String.valueOf(key), value));
        return normalized;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> findNamedSection(Object sectionObject, String name, String nestedKey) {
        if (!(sectionObject instanceof List<?> sectionList) || name == null) {
            return null;
        }
        for (Object item : sectionList) {
            if (!(item instanceof Map<?, ?> itemMap)) {
                continue;
            }
            Object candidateName = itemMap.get("name");
            if (name.equals(candidateName)) {
                Object nested = itemMap.get(nestedKey);
                if (nested instanceof Map<?, ?> nestedMap) {
                    Map<String, Object> normalized = new LinkedHashMap<>();
                    nestedMap.forEach((key, value) -> normalized.put(String.valueOf(key), value));
                    return normalized;
                }
                return null;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> nestedMap(Map<String, Object> parent, String key) {
        if (parent == null) {
            return null;
        }
        Object nested = parent.get(key);
        if (!(nested instanceof Map<?, ?> nestedMap)) {
            return null;
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        nestedMap.forEach((nestedKey, value) -> normalized.put(String.valueOf(nestedKey), value));
        return normalized;
    }

    private String findExecArgumentValue(Map<String, Object> execSection, String flagName) {
        if (execSection == null) {
            return null;
        }
        Object argsObject = execSection.get("args");
        if (!(argsObject instanceof List<?> argsList)) {
            return null;
        }
        List<String> args = new ArrayList<>();
        for (Object item : argsList) {
            args.add(String.valueOf(item));
        }
        for (int index = 0; index < args.size(); index++) {
            String arg = args.get(index);
            if (flagName.equals(arg) && index + 1 < args.size()) {
                return trimToNull(args.get(index + 1));
            }
            String prefix = flagName + "=";
            if (arg.startsWith(prefix)) {
                return trimToNull(arg.substring(prefix.length()));
            }
        }
        return null;
    }

    private Object mapValue(Map<String, Object> map, String key) {
        return map == null ? null : map.get(key);
    }

    private String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private String safeHost(String apiServer) {
        try {
            return URI.create(apiServer).getHost();
        } catch (Exception e) {
            return "<unparseable>";
        }
    }

    record AzureKubeConfigMaterial(
            String apiServer,
            byte[] clusterCaBytes,
            String serverApplicationId,
            String currentContextName,
            String userAuthMode,
            String serverHost) {
    }
}
