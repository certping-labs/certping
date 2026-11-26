// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
/**
 * Validates {@code CredentialReferenceEntity.configJson} for Kubernetes deployment credentials.
 *
 * <p>In this system, credential <em>values</em> live in the secret-store entry pointed to by
 * {@code credential_references.secret_handle}. The {@code credential_references.config} JSONB field holds
 * CertPing's non-secret metadata.
 *
 * <p>For {@code provider=KUBERNETES_SECRETS} we enforce a strict schema so downstream deploy commands and
 * the agent receive predictable configuration:
 * <pre>{@code
 * {
 *   "authMethod": "AWS",              // one of: AWS | AZURE | GCP | SA_TOKEN | SA_INCLUSTER
 *   "clusterName": "prod",            // non-empty string
 *   "namespaces": ["dev", "prod"]     // OR literal string "all_namespaces"
 * }
 * }</pre>
 *
 * <p>Unknown keys are rejected (defense-in-depth and future compatibility: new fields must be added
 * deliberately). This validator is invoked on both credential creation and credential updates.
 */
public class KubernetesDeploymentConfigValidator {

    private static final String PROVIDER_KUBERNETES_SECRETS = "KUBERNETES_SECRETS";
    private static final String ALL_NAMESPACES = "all_namespaces";
    private static final Set<String> ALLOWED_AUTH_METHODS =
            Set.of("AWS", "AZURE", "GCP", "SA_TOKEN", "SA_INCLUSTER");
    private static final Set<String> ALLOWED_KEYS =
            Set.of("authMethod", "clusterName", "namespaces");

    private final ObjectMapper objectMapper;

    /**
     * Validates {@code configJson} only when {@code provider} is {@code KUBERNETES_SECRETS}.
     * All other providers are treated as out-of-scope for this validator.
     */
    public void validateForProvider(String provider, String configJson) {
        if (!PROVIDER_KUBERNETES_SECRETS.equals(provider)) {
            return;
        }
        validateKubernetesConfig(configJson);
    }

    private void validateKubernetesConfig(String configJson) {
        if (configJson == null || configJson.isBlank()) {
            throw new BadRequestException(
                    "configJson is required when provider is KUBERNETES_SECRETS");
        }

        Map<String, Object> root;
        try {
            root = objectMapper.readValue(configJson, new TypeReference<>() {});
        } catch (Exception ex) {
            throw new BadRequestException("configJson must be valid JSON object", ex);
        }

        if (root == null || root.isEmpty()) {
            throw new BadRequestException(
                    "configJson must be a non-empty JSON object for KUBERNETES_SECRETS");
        }

        for (String key : root.keySet()) {
            if (!ALLOWED_KEYS.contains(key)) {
                throw new BadRequestException(
                        "configJson contains unsupported key '" + key +
                                "'. Allowed keys: authMethod, clusterName, namespaces");
            }
        }

        Object authMethodRaw = root.get("authMethod");
        if (!(authMethodRaw instanceof String authMethod) || authMethod.isBlank()) {
            throw new BadRequestException("configJson.authMethod is required and must be a string");
        }
        if (!ALLOWED_AUTH_METHODS.contains(authMethod)) {
            throw new BadRequestException(
                    "configJson.authMethod must be one of " + ALLOWED_AUTH_METHODS);
        }

        Object clusterNameRaw = root.get("clusterName");
        if (!(clusterNameRaw instanceof String clusterName) || clusterName.isBlank()) {
            throw new BadRequestException("configJson.clusterName is required and must be a non-empty string");
        }

        Object namespacesRaw = root.get("namespaces");
        if (namespacesRaw instanceof String namespacesAsString) {
            if (!ALL_NAMESPACES.equals(namespacesAsString)) {
                throw new BadRequestException(
                        "configJson.namespaces string value must be exactly 'all_namespaces'");
            }
            return;
        }

        if (!(namespacesRaw instanceof List<?> namespaces) || namespaces.isEmpty()) {
            throw new BadRequestException(
                    "configJson.namespaces must be either 'all_namespaces' or a non-empty array of namespace names");
        }

        Set<String> unique = new HashSet<>();
        for (Object item : namespaces) {
            if (!(item instanceof String namespace) || namespace.isBlank()) {
                throw new BadRequestException("configJson.namespaces array must contain non-empty strings only");
            }
            if (!unique.add(namespace)) {
                throw new BadRequestException("configJson.namespaces must not contain duplicates");
            }
        }
    }
}
