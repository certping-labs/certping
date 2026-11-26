// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

@Slf4j
@Component
@DeploymentAdapterFor(TargetType.KUBERNETES_SECRETS)
@RequiredArgsConstructor
public class KubernetesDeploymentAdapter implements DeploymentAdapter {

    private static final String ALL_NAMESPACES_KEY = "all_namespaces";

    private final KubernetesSecretService kubernetesSecretService;
    private final KubernetesAuthService kubernetesAuthService;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        KubernetesDeploymentConfig config = parseConfig(message.getConfigJson());
        String clusterName = requireClusterName(config.clusterName());
        String domain = resolveDomain(message, bundle);

        log.info("Kubernetes deployment: clusterName={}, xref={}, authProvider={}, explicitNamespaceCount={}",
                clusterName,
                message.getCertificateXref(),
                config.authProvider(),
                config.namespaceSecretNames().size());

        Supplier<KubernetesSecretService.KubernetesAuthConfig> authConfigSupplier =
                () -> kubernetesAuthService.resolve(config.authProvider(), clusterName, message);

        KubernetesSecretService.KubernetesDeploymentSummary summary =
                kubernetesSecretService.deployTlsSecrets(
                        bundle,
                        clusterName,
                        domain,
                        authConfigSupplier,
                        supportsAuthRefresh(config.authProvider()),
                        config.namespaceSecretNames(),
                        config.allNamespaces(),
                        message.getOrganizationId(),
                        message.getCertificateXref());

        String targetResourceId = "k8s://" + clusterName + "/tls-secrets/" + summary.namespaceCount();
        return DeploymentResult.of(targetResourceId);
    }

    /**
     * Keeping config validation in the adapter prevents malformed transport payloads from reaching Kubernetes calls.
     * That fail-fast boundary makes retry behavior safer because permanent payload defects do not trigger cluster writes.
     */
    private KubernetesDeploymentConfig parseConfig(String configJson) {
        if (configJson == null || configJson.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_MISSING",
                    "Kubernetes deployment requires configJson with authProvider, clusterName and nsMaps");
        }

        try {
            JsonNode root = objectMapper.readTree(configJson);
            String clusterName = textValue(root.get("clusterName"));
            KubernetesAuthProvider authProvider = KubernetesAuthProvider.fromConfigValue(textValue(root.get("authProvider")));
            NamespaceSelection selection = parseNamespaceSelection(root.get("nsMaps"));
            return new KubernetesDeploymentConfig(clusterName, authProvider,
                    selection.namespaceSecretNames(), selection.allNamespaces());
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Failed to parse Kubernetes deployment configJson: " + e.getMessage(), e);
        }
    }

    private NamespaceSelection parseNamespaceSelection(JsonNode nsMapsNode) {
        if (nsMapsNode == null || nsMapsNode.isNull()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment config must include nsMaps. Use namespace mappings or {\"all_namespaces\":\"secret-name\"}.");
        }

        if (nsMapsNode.isString()) {
            String mode = textValue(nsMapsNode);
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Unsupported nsMaps mode: '" + mode + "'. Use namespace mappings or {\"all_namespaces\":\"secret-name\"}.");
        }

        Map<String, String> namespaceSecretNames = new LinkedHashMap<>();

        if (nsMapsNode.isObject()) {
            JsonNode allNamespacesSecretName = nsMapsNode.get(ALL_NAMESPACES_KEY);
            if (allNamespacesSecretName != null) {
                if (nsMapsNode.size() != 1) {
                    throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                            "Kubernetes nsMaps cannot mix all_namespaces with explicit namespace mappings");
                }
                putUniqueNamespaceMapping(namespaceSecretNames, ALL_NAMESPACES_KEY, textValue(allNamespacesSecretName));
                return new NamespaceSelection(namespaceSecretNames, true);
            }

            Iterator<Map.Entry<String, JsonNode>> fields = nsMapsNode.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                putUniqueNamespaceMapping(namespaceSecretNames, entry.getKey(), textValue(entry.getValue()));
            }
            return new NamespaceSelection(namespaceSecretNames, false);
        }

        if (!nsMapsNode.isArray()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment nsMaps must be an object or an array of single-entry objects");
        }

        // Server payloads currently use array-of-single-entry maps; normalize once to keep the service simple.
        for (JsonNode item : nsMapsNode) {
            if (item == null || !item.isObject() || item.size() != 1) {
                throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                        "Each Kubernetes nsMaps entry must be a single-entry object");
            }
            Iterator<Map.Entry<String, JsonNode>> fields = item.properties().iterator();
            Map.Entry<String, JsonNode> entry = fields.next();
            if (ALL_NAMESPACES_KEY.equals(entry.getKey())) {
                throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                        "Use object form {\"all_namespaces\":\"secret-name\"} for all_namespaces mode");
            }
            putUniqueNamespaceMapping(namespaceSecretNames, entry.getKey(), textValue(entry.getValue()));
        }
        return new NamespaceSelection(namespaceSecretNames, false);
    }

    private void putUniqueNamespaceMapping(Map<String, String> namespaceSecretNames, String namespace, String secretName) {
        if (namespaceSecretNames.putIfAbsent(namespace, secretName) != null) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment config contains duplicate namespace mapping for '" + namespace + "'");
        }
    }

    private String requireClusterName(String clusterName) {
        if (clusterName == null || clusterName.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment configJson must include a non-blank clusterName");
        }
        return clusterName.trim();
    }

    private String resolveDomain(CertDeploymentMessage message, CertificateBundle bundle) {
        String fromMessage = CertificateIdentityUtils.normaliseDomain(message.getDomain());
        if (!fromMessage.isBlank()) {
            return fromMessage;
        }

        return CertificateIdentityUtils.extractPrimaryDomainFromPem(bundle.leafCertificate())
                .orElseThrow(() -> new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                        "Kubernetes deployment requires domain in the message or a parsable leaf certificate"));
    }

    private String textValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isString()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment config values must be strings");
        }
        return node.asString();
    }

    private boolean supportsAuthRefresh(KubernetesAuthProvider authProvider) {
        return switch (authProvider) {
            case AWS, GCP, AZURE, SA_TOKEN -> true;
            case SA_INCLUSTER -> false;
        };
    }

    private record NamespaceSelection(Map<String, String> namespaceSecretNames, boolean allNamespaces) {
    }

    private record KubernetesDeploymentConfig(
            String clusterName,
            KubernetesAuthProvider authProvider,
            Map<String, String> namespaceSecretNames,
            boolean allNamespaces) {
    }
}
