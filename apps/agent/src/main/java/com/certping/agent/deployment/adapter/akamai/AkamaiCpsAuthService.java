// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.akamai.edgegrid.signer.ClientCredential;
import com.akamai.edgegrid.signer.apachehttpclient5.ApacheHttpClient5EdgeGridInterceptor;
import com.akamai.edgegrid.signer.apachehttpclient5.ApacheHttpClient5EdgeGridRoutePlanner;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.AkamaiCpsDeploymentCredential;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.springframework.stereotype.Component;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.util.TimeValue;

/**
 * Reusable Akamai CPS auth and client setup.
 *
 * <p>Deployment and discovery should share this boundary so EdgeGrid auth is not duplicated.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AkamaiCpsAuthService {

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;

    AkamaiCpsDeploymentCredential loadCredential(String credentialKvPath) {
        String raw = secretStore.read(credentialKvPath);
        return parseCredential(raw);
    }

    AkamaiCpsDeploymentCredential parseCredential(String raw) {
        try {
            AkamaiCpsDeploymentCredential cred = objectMapper.readValue(raw, AkamaiCpsDeploymentCredential.class);
            requireField("host", cred.getHost());
            requireField("clientToken", cred.getClientToken());
            requireField("accessToken", cred.getAccessToken());
            requireField("clientSecret", cred.getClientSecret());
            if (cred.getEnrollments() == null || cred.getEnrollments().isEmpty()) {
                throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                        "Akamai credential missing enrollments list");
            }
            return cred;
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse Akamai deployment credential JSON: " + e.getMessage(), e);
        }
    }

    CloseableHttpClient buildClient(AkamaiCpsDeploymentCredential cred) {
        ClientCredential clientCredential = ClientCredential.builder()
                .host(requireField("host", cred.getHost()))
                .clientToken(requireField("clientToken", cred.getClientToken()))
                .accessToken(requireField("accessToken", cred.getAccessToken()))
                .clientSecret(requireField("clientSecret", cred.getClientSecret()))
                .build();

        return edgeGridClient(clientCredential);
    }

    String baseUrl(AkamaiCpsDeploymentCredential cred) {
        return "https://" + requireField("host", cred.getHost());
    }

    // ----- scope+KV-secret-based builders for the deployment adapter -----

    /** Build an EdgeGrid HTTP client from a typed KV secret + scope host. */
    public CloseableHttpClient buildClient(AkamaiKvSecret kv, String host) {
        ClientCredential clientCredential = ClientCredential.builder()
                .host(requireField("host", host))
                .clientToken(requireField("clientToken", kv.clientToken()))
                .accessToken(requireField("accessToken", kv.accessToken()))
                .clientSecret(requireField("clientSecret", kv.clientSecret()))
                .build();

        return edgeGridClient(clientCredential);
    }

    public String baseUrl(String host) {
        return "https://" + requireField("host", host);
    }

    public AkamaiKvSecret parseKvSecret(String credentialKvPath) {
        try {
            String raw = secretStore.read(credentialKvPath);
            return objectMapper.readValue(raw, AkamaiKvSecret.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse Akamai KV secret JSON: " + e.getMessage(), e);
        }
    }

    private String requireField(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Akamai credential missing required field: " + name);
        }
        return value.trim();
    }

    private static CloseableHttpClient edgeGridClient(ClientCredential clientCredential) {
        return HttpClientBuilder.create()
                .addRequestInterceptorFirst(new ApacheHttpClient5EdgeGridInterceptor(clientCredential))
                .setRoutePlanner(new ApacheHttpClient5EdgeGridRoutePlanner(clientCredential))
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setDefaultConnectionConfig(ConnectionConfig.custom()
                                .setTimeToLive(TimeValue.ofSeconds(30))
                                .build())
                        .build())
                .build();
    }
}
