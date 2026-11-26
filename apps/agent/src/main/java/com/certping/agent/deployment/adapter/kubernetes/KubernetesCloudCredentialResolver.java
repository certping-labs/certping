// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.WorkloadIdentityCredentialBuilder;
import com.certping.agent.deployment.adapter.aws.AwsAssumeRoleService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.KubernetesDeploymentCredential;
import com.google.auth.oauth2.GoogleCredentials;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Resolves which credential source a cloud-backed Kubernetes deployment should use.
 *
 * <p>The deployment message always names the target cluster through provider metadata stored in Key Vault.
 * This resolver decides whether the actual cloud identity comes from explicit secret material in that payload
 * or from workload identity already attached to the running pod.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class KubernetesCloudCredentialResolver {

    private static final String AZURE_FEDERATED_TOKEN_FILE_ENV = "AZURE_FEDERATED_TOKEN_FILE";

    private final AwsAssumeRoleService awsAssumeRoleService;

    /**
     * Precedence is intentionally explicit:
     * 1) static keys win when present because the payload fully describes the auth source
     * 2) role-only falls back to workload identity so pods can reach remote clusters without stored AWS keys
     * 3) "nothing usable" is a hard config error instead of an implicit ambient-credential fallback
     */
    AwsCredentialsProvider resolveAwsCredentialsProvider(KubernetesDeploymentCredential credential, Region region) {
        String accessKeyId = trimToNull(credential.getAwsAccessKeyId());
        String secretAccessKey = trimToNull(credential.getAwsSecretAccessKey());
        String roleArn = trimToNull(credential.getAwsRoleArn());

        if ((accessKeyId == null) != (secretAccessKey == null)) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes AWS credential must include both awsAccessKeyId and awsSecretAccessKey when using static keys");
        }

        if (accessKeyId != null) {
            if (roleArn != null) {
                AwsSessionCredentials sessionCredentials = awsAssumeRoleService.assumeRole(roleArn, region.id(), accessKeyId, secretAccessKey);
                return StaticCredentialsProvider.create(sessionCredentials);
            }

            AwsBasicCredentials staticCreds = AwsBasicCredentials.create(accessKeyId, secretAccessKey);
            return StaticCredentialsProvider.create(staticCreds);
        }

        if (roleArn == null) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes AWS credential must include awsAccessKeyId/awsSecretAccessKey or awsRoleArn for workload identity");
        }

        log.info("Kubernetes AWS auth selected workload identity bootstrap for roleArn={} region={}", roleArn, region.id());
        AwsSessionCredentials sessionCredentials = awsAssumeRoleService.assumeRole(roleArn, region.id(), null, null);
        return StaticCredentialsProvider.create(sessionCredentials);
    }

    /**
     * Azure has two supported sources for the ARM credential used to fetch AKS user kubeconfig:
     * explicit client credentials from Key Vault, or federated workload identity projected into the pod.
     */
    TokenCredential resolveAzureTokenCredential(
            String tenantId,
            String subscriptionId,
            String resourceGroup,
            String clientId,
            String clientSecret) {
        if (clientSecret != null) {
            String requiredClientId = requireNonBlank(clientId, "DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes AZURE credential is missing azureClientId").trim();
            log.info("Kubernetes Azure auth selected explicit client secret flow for subscriptionId={} resourceGroup={}",
                    subscriptionId, resourceGroup);
            return createAzureClientSecretCredential(tenantId, requiredClientId, clientSecret);
        }

        String requiredClientId = requireNonBlank(clientId, "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE workload identity requires azureClientId").trim();
        String tokenFilePath = requireNonBlank(readEnvironmentVariable(AZURE_FEDERATED_TOKEN_FILE_ENV),
                "DEPLOY_K8S_CREDENTIAL_INVALID",
                "Kubernetes AZURE workload identity requires AZURE_FEDERATED_TOKEN_FILE to be set");
        log.info("Kubernetes Azure auth selected workload identity flow for subscriptionId={} resourceGroup={}",
                subscriptionId, resourceGroup);
        return createAzureWorkloadIdentityCredential(tenantId, requiredClientId, tokenFilePath);
    }

    /**
     * GCP follows the same precedence rule as the other providers:
     * explicit service-account material wins, otherwise we rely on the runtime's application default credentials.
     */
    GoogleCredentials resolveGcpCredentials(KubernetesDeploymentCredential credential) throws Exception {
        byte[] serviceAccountBytes = resolveGcpServiceAccountJsonBytesIfPresent(credential);
        if (serviceAccountBytes != null) {
            log.info("Kubernetes GCP auth selected explicit service account flow for projectId={} location={}",
                    credential.getGcpProjectId(), credential.getGcpLocation());
            return GoogleCredentials.fromStream(new ByteArrayInputStream(serviceAccountBytes));
        }

        log.info("Kubernetes GCP auth selected application default credentials flow for projectId={} location={}",
                credential.getGcpProjectId(), credential.getGcpLocation());
        return createGoogleApplicationDefaultCredentials();
    }

    TokenCredential createAzureClientSecretCredential(String tenantId, String clientId, String clientSecret) {
        return new ClientSecretCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

    TokenCredential createAzureWorkloadIdentityCredential(String tenantId, String clientId, String tokenFilePath) {
        return new WorkloadIdentityCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .tokenFilePath(tokenFilePath)
                .build();
    }

    GoogleCredentials createGoogleApplicationDefaultCredentials() throws Exception {
        return GoogleCredentials.getApplicationDefault();
    }

    String readEnvironmentVariable(String name) {
        return System.getenv(name);
    }

    private byte[] resolveGcpServiceAccountJsonBytesIfPresent(KubernetesDeploymentCredential credential) {
        String json = trimToNull(credential.getGcpServiceAccountJson());
        if (json != null) {
            return json.getBytes(StandardCharsets.UTF_8);
        }

        String encoded = trimToNull(credential.getGcpServiceAccountJsonBase64());
        if (encoded == null) {
            return null;
        }

        try {
            return Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes GCP credential gcpServiceAccountJsonBase64 is not valid Base64", e);
        }
    }

    private String requireNonBlank(String value, String code, String message) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException(code, message);
        }
        return value;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
