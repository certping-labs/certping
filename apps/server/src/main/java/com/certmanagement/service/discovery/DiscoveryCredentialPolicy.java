// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class DiscoveryCredentialPolicy {

    private static final String TARGET_KUBERNETES_SECRETS = "KUBERNETES_SECRETS";
    private static final String ALL_NAMESPACES = "all_namespaces";
    private static final Pattern KUBERNETES_CLUSTER_NAME =
            Pattern.compile("[A-Za-z0-9._-]{1,253}");
    private static final Pattern KUBERNETES_NAMESPACE_NAME =
            Pattern.compile("[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?");
    private static final Set<String> KUBERNETES_AUTH_METHODS = Set.of(
            "SA_INCLUSTER", "SA_TOKEN", "AWS", "AZURE", "GCP");
    private static final Set<String> AWS_PROVIDERS = Set.of(
            "AWS_ACM", "AWS_ALB", "AWS_NLB", "AWS_API_GW_REST", "AWS_API_GW_HTTP", "AWS_CLOUDFRONT",
            "AWS_ORGANIZATION");
    private static final Set<String> AZURE_PROVIDERS = Set.of(
            "AZURE_KV", "AZURE_APP_GW", "AZURE_APP_GW_CONTAINERS", "AZURE_AFD");
    private static final Set<String> GCP_PROVIDERS = Set.of(
            "GCP_CERT_MANAGER", "GCP_ALB", "GCP_PROXY_NLB", "GCP_API_GW", "GCP_CLOUD_CDN");

    /**
     * The target types the agent can discover (its DiscoveryAdapterFactory): AWS ACM by region, AWS
     * Organization ACM, Azure Key Vault and Kubernetes.
     */
    public static final Set<String> DISCOVERABLE_TARGETS = Set.of(
            "AWS_ACM", "AWS_ORGANIZATION", "AZURE_KV", TARGET_KUBERNETES_SECRETS);

    /**
     * AWS load balancer, CDN and API types: the agent runs the same ACM region listing for each of
     * them, so they are not separate discovery targets.
     */
    static final Set<String> AWS_ACM_ALIASES = Set.of(
            "AWS_ALB", "AWS_NLB", "AWS_CLOUDFRONT", "AWS_API_GW_REST", "AWS_API_GW_HTTP");

    static final String USE_AWS_ACM = "use AWS ACM (region) discovery; it covers certificates attached to "
            + "ALB, NLB, CloudFront and API Gateway";

    private final ObjectMapper objectMapper;

    /**
     * Why discovery cannot run for {@code targetType}, or null when it can. The agent has
     * no adapter for Azure Application Gateway, Front Door, Application Gateway for Containers or any
     * GCP type, and the AWS ALB, NLB, CloudFront and API Gateway types only repeat the ACM listing.
     */
    public static String unsupportedTargetReason(String targetType) {
        String target = targetType == null ? "" : targetType.trim().toUpperCase(Locale.ROOT);
        if (DISCOVERABLE_TARGETS.contains(target)) {
            return null;
        }
        if (AWS_ACM_ALIASES.contains(target)) {
            return "Discovery for " + target + " is not a separate target: " + USE_AWS_ACM + ".";
        }
        if (AZURE_PROVIDERS.contains(target) || GCP_PROVIDERS.contains(target) || target.startsWith("GCP_")) {
            return "Discovery is not available for " + target + ". Supported discovery targets: AWS ACM (region) "
                    + "(AWS_ACM), AWS Organization ACM (AWS_ORGANIZATION), Azure Key Vault (AZURE_KV) and "
                    + "Kubernetes (KUBERNETES_SECRETS).";
        }
        return "Unknown discovery targetType '" + target + "'. Supported discovery targets: AWS_ACM, "
                + "AWS_ORGANIZATION, AZURE_KV and KUBERNETES_SECRETS.";
    }

    /** 400 for a target type the agent cannot discover; see {@link #unsupportedTargetReason}. */
    public static void requireDiscoverableTargetStatic(String targetType) {
        String reason = unsupportedTargetReason(targetType);
        if (reason != null) {
            throw new BadRequestException(reason);
        }
    }

    public void validateProvider(CredentialReferenceEntity credential, String targetType) {
        String provider = credential.getProvider();
        if (provider != null && "AWS_ACM".equalsIgnoreCase(targetType)
                && AWS_ACM_ALIASES.contains(provider.toUpperCase(Locale.ROOT))) {
            // An ALB, NLB, CloudFront or API Gateway credential is an AWS credential for the same ACM listing.
            return;
        }
        if (provider != null && !provider.isBlank()
                && targetType != null && !targetType.isBlank()
                && !provider.equalsIgnoreCase(targetType)) {
            throw new BadRequestException(
                    "Credential '" + credential.getCredentialXref() + "' is for provider '" + provider
                            + "', but discovery was requested for targetType '" + targetType
                            + "'. Pick a credential that matches the target type.");
        }
    }

    public void validateAuthentication(CredentialReferenceEntity credential) {
        if (hasKvPath(credential)
                || allowsNullKvPath(credential.getProvider(), credential.getConfigJson())) {
            return;
        }
        throw new BadRequestException(
                "Credential '" + credential.getCredentialXref() + "' has no KV path configured, "
                        + "cannot use for discovery");
    }

    public String toDiscoveryScopeJson(CredentialReferenceEntity credential) {
        if (!TARGET_KUBERNETES_SECRETS.equals(credential.getProvider())) {
            return credential.getConfigJson();
        }
        String configJson = credential.getConfigJson();
        if (configJson == null || configJson.isBlank()) {
            throw new BadRequestException("configJson is required when provider is KUBERNETES_SECRETS");
        }
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode authMethod = root.path("authMethod");
            JsonNode clusterName = root.path("clusterName");
            JsonNode namespaces = root.path("namespaces");
            if (!authMethod.isString() || authMethod.asString().isBlank()
                    || !clusterName.isString() || clusterName.asString().isBlank()
                    || namespaces.isMissingNode() || namespaces.isNull()) {
                throw new BadRequestException(
                        "Kubernetes discovery credential config requires authMethod, clusterName, and namespaces");
            }
            String normalizedAuthMethod = normalizeKubernetesAuthMethod(authMethod.asString());
            String normalizedClusterName = validateKubernetesClusterName(clusterName.asString());
            ObjectNode discoveryScope = objectMapper.createObjectNode();
            discoveryScope.put("authProvider", normalizedAuthMethod);
            discoveryScope.put("clusterName", normalizedClusterName);
            discoveryScope.set("namespaces", sortedNamespaces(namespaces));
            return objectMapper.writeValueAsString(discoveryScope);
        } catch (BadRequestException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new BadRequestException("Unable to prepare Kubernetes discovery credential scope", exception);
        }
    }

    private boolean allowsNullKvPath(String provider, String configJson) {
        if (TARGET_KUBERNETES_SECRETS.equals(provider)
                && "SA_INCLUSTER".equals(extractText(configJson, "authMethod"))) {
            return true;
        }
        String authMode = extractText(configJson, "authMode");
        return (AWS_PROVIDERS.contains(provider)
                    && ("INSTANCE_PROFILE".equals(authMode) || "ASSUME_ROLE".equals(authMode)))
                || (AZURE_PROVIDERS.contains(provider) && "WORKLOAD_IDENTITY".equals(authMode))
                || (GCP_PROVIDERS.contains(provider) && "WORKLOAD_IDENTITY".equals(authMode));
    }

    private JsonNode sortedNamespaces(JsonNode namespaces) {
        if (namespaces.isString()) {
            if (ALL_NAMESPACES.equals(namespaces.asString())) {
                return namespaces;
            }
            throw new BadRequestException(
                    "Kubernetes discovery namespaces must be an array or the string all_namespaces");
        }
        if (!namespaces.isArray()) {
            throw new BadRequestException(
                    "Kubernetes discovery namespaces must be an array or the string all_namespaces");
        }
        List<String> values = new ArrayList<>();
        namespaces.forEach(namespace -> {
            if (!namespace.isString() || namespace.asString().isBlank()) {
                throw new BadRequestException("Kubernetes discovery namespaces must contain non-blank strings");
            }
            String namespaceName = namespace.asString().trim();
            if (!KUBERNETES_NAMESPACE_NAME.matcher(namespaceName).matches()) {
                throw new BadRequestException(
                        "Kubernetes discovery namespaces must contain valid Kubernetes namespace names");
            }
            values.add(namespaceName);
        });
        if (values.isEmpty()) {
            throw new BadRequestException(
                    "Kubernetes discovery namespaces must not be empty; use all_namespaces or explicit namespaces");
        }
        ArrayNode sorted = objectMapper.createArrayNode();
        values.stream().distinct().sorted().forEach(sorted::add);
        return sorted;
    }

    private String normalizeKubernetesAuthMethod(String authMethod) {
        String normalized = authMethod.trim().toUpperCase(Locale.ROOT);
        if (!KUBERNETES_AUTH_METHODS.contains(normalized)) {
            throw new BadRequestException(
                    "Kubernetes discovery authMethod must be one of SA_INCLUSTER, SA_TOKEN, AWS, AZURE, or GCP");
        }
        return normalized;
    }

    private String validateKubernetesClusterName(String clusterName) {
        String normalized = clusterName.trim();
        if (!KUBERNETES_CLUSTER_NAME.matcher(normalized).matches()) {
            throw new BadRequestException(
                    "Kubernetes discovery clusterName must use letters, digits, dots, underscores, or hyphens");
        }
        return normalized;
    }

    private boolean hasKvPath(CredentialReferenceEntity credential) {
        return credential.getSecretHandle() != null && !credential.getSecretHandle().isBlank();
    }

    private String extractText(String configJson, String fieldName) {
        if (configJson == null || configJson.isBlank()) {
            return null;
        }
        try {
            JsonNode value = objectMapper.readTree(configJson).get(fieldName);
            return value != null && value.isString() && !value.asString().isBlank()
                    ? value.asString()
                    : null;
        } catch (Exception exception) {
            return null;
        }
    }
}
