// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.ClientBuilder;
import io.kubernetes.client.util.KubeConfig;
import io.kubernetes.client.util.credentials.AccessTokenAuthentication;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;

@Slf4j
@Component
public class KubernetesApiClientFactory {

    /**
     * Builds a Kubernetes API client from the normalized auth config.
     *
     * <p>In-cluster mode follows the upstream Java client pattern:
     * https://github.com/kubernetes-client/java/blob/master/examples/examples-release-latest/src/main/java/io/kubernetes/client/examples/InClusterClientExample.java
     */
    public ApiClient buildApiClient(KubernetesSecretService.KubernetesAuthConfig authConfig) {
        try {
            if (authConfig.inCluster()) {
                return ClientBuilder.cluster().build();
            }
            if (authConfig.kubeConfigYaml() != null && !authConfig.kubeConfigYaml().isBlank()) {
                KubeConfig kubeConfig = KubeConfig.loadKubeConfig(new StringReader(authConfig.kubeConfigYaml()));
                String kubeApiServer = kubeConfig.getServer();
                if (kubeApiServer == null || kubeApiServer.isBlank()) {
                    throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                            "Kubernetes kubeconfig is missing current cluster server endpoint");
                }
                return ClientBuilder.kubeconfig(kubeConfig).build();
            }

            String apiServer = requireDirectApiServer(authConfig.apiServer());
            String bearerToken = requireDirectBearerToken(authConfig.bearerToken());
            byte[] clusterCaCertPem = requireDirectClusterCa(authConfig.clusterCaCertPem());

            log.debug(
                    "Building Kubernetes client from direct bearer token auth serverHost={} caBytes={} tokenPresent={}",
                    safeHost(apiServer),
                    clusterCaCertPem.length,
                    true);

            return new ClientBuilder()
                    .setBasePath(apiServer)
                    .setVerifyingSsl(true)
                    .setCertificateAuthority(clusterCaCertPem)
                    .setAuthentication(new AccessTokenAuthentication(bearerToken))
                    .build();
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes client configuration is invalid: " + e.getMessage(), e);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (IOException e) {
            throw new TransientAgentException("DEPLOY_K8S_CLIENT_INIT_FAILED",
                    "Failed to initialize Kubernetes client: " + e.getMessage(), e);
        }
    }

    KubeApis.Core buildCoreV1Api(KubernetesSecretService.KubernetesAuthConfig authConfig) {
        return new KubeApis.Core(buildApiClient(authConfig));
    }

    private String requireDirectApiServer(String apiServer) {
        String normalized = apiServer == null ? null : apiServer.trim();
        if (normalized == null || normalized.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth is missing apiServer");
        }

        try {
            URI uri = URI.create(normalized);
            if (uri.getScheme() == null || uri.getScheme().isBlank() || uri.getHost() == null || uri.getHost().isBlank()) {
                throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                        "Kubernetes direct-token auth apiServer must be an absolute URL");
            }
            return normalized;
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth apiServer is not a valid URL", e);
        }
    }

    private String requireDirectBearerToken(String bearerToken) {
        String normalized = bearerToken == null ? null : bearerToken.trim();
        if (normalized == null || normalized.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth is missing bearerToken");
        }
        return normalized;
    }

    private byte[] requireDirectClusterCa(byte[] clusterCaCertPem) {
        if (clusterCaCertPem == null || clusterCaCertPem.length == 0) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth is missing cluster CA certificate");
        }
        return clusterCaCertPem;
    }

    private String safeHost(String apiServer) {
        try {
            URI uri = URI.create(apiServer);
            String host = uri.getHost();
            return host == null || host.isBlank() ? "<unknown>" : host;
        } catch (IllegalArgumentException e) {
            return "<invalid>";
        }
    }
}
