// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesAuthService;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesSecretService;
import com.certping.agent.deployment.cloud.azure.AzureAuthSecret;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Azure Application Gateway for Containers deployment adapter.
 *
 * <p>One credential = one AGC cluster + namespace. The cluster name, AGC namespace,
 * gateway name, and allowed secret namespaces all live in the credential scope.
 * Per-cert targets select which namespace/secretName pairs to deploy TLS secrets to.
 *
 * <p>TLS is delivered via Kubernetes Secrets. The adapter groups target secrets by
 * namespace and calls {@link KubernetesSecretService#deployTlsSecretsForNamespace}
 * for each.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AZURE_APP_GW_CONTAINERS)
@RequiredArgsConstructor
public class AzureAgcDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "Azure AGC";

    private final SecretStore secretStore;
    private final KubernetesSecretService kubernetesSecretService;
    private final KubernetesAuthService kubernetesAuthService;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AzureAgcScope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);

        AzureAgcTargets targets = parseTargets(message.getTargetsJson());
        List<AzureAgcTargets.SecretRef> secretRefs = validateTargets(targets, scope);

        String clusterAuthMode = scope.clusterAuthMode();
        boolean isInCluster = "SA_INCLUSTER".equalsIgnoreCase(clusterAuthMode);

        AzureAuthSecret kvSecret = readKvSecret(message);

        Supplier<KubernetesSecretService.KubernetesAuthConfig> authConfigSupplier =
                () -> buildAuthConfig(scope, kvSecret, isInCluster, message.getCertificateXref());

        String domain = resolveDomain(message, bundle);

        // Group targets by namespace
        Map<String, Map<String, String>> byNamespace = groupByNamespace(secretRefs, domain);

        List<KubernetesSecretService.AppliedSecret> allApplied = new ArrayList<>();
        List<String> allDeployedRefs = new ArrayList<>();
        int namespaceCount = 0;

        for (Map.Entry<String, Map<String, String>> entry : byNamespace.entrySet()) {
            String namespace = entry.getKey();
            Map<String, String> secretDomainMap = entry.getValue();

            KubernetesSecretService.KubernetesDeploymentSummary summary =
                    kubernetesSecretService.deployTlsSecretsForNamespace(
                            bundle,
                            scope.clusterName(),
                            authConfigSupplier,
                            !isInCluster,
                            namespace,
                            secretDomainMap,
                            message.getOrganizationId(),
                            message.getCertificateXref());

            allApplied.addAll(summary.appliedSecrets());
            allDeployedRefs.addAll(summary.deployedSecretRefs());
            namespaceCount += summary.namespaceCount();
        }

        log.info("Azure AGC deployment complete: cluster={}, namespaces={}, secrets={}, xref={}",
                scope.clusterName(), byNamespace.size(), allDeployedRefs.size(),
                message.getCertificateXref());

        String targetResourceId = "agc://" + scope.clusterName()
                + "/" + scope.agcNamespace()
                + "/tls-secrets/" + allDeployedRefs.size();
        return DeploymentResult.of(targetResourceId,
                toResultJson(scope.clusterName(), scope.agcNamespace(), allApplied));
    }

    void validateScope(AzureAgcScope scope) {
        requireField(scope.clusterName(), "scope.clusterName");
        requireField(scope.agcNamespace(), "scope.agcNamespace");
        if (scope.secretNamespaces() == null || scope.secretNamespaces().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: scope.secretNamespaces");
        }
        String apiStyle = scope.apiStyle();
        if (apiStyle != null && !apiStyle.isBlank()) {
            String normalized = apiStyle.trim().toLowerCase();
            if (!"gateway".equals(normalized) && !"gateway_api".equals(normalized)
                    && !"ingress".equals(normalized)) {
                throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                        CTX + " scope.apiStyle must be 'GATEWAY_API' or 'INGRESS'");
            }
        }
    }

    List<AzureAgcTargets.SecretRef> validateTargets(AzureAgcTargets targets, AzureAgcScope scope) {
        if (targets.secrets() == null || targets.secrets().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    CTX + " requires non-empty targets.secrets");
        }
        Set<String> scopeNamespaces = new LinkedHashSet<>(scope.secretNamespaces());
        Set<String> seen = new LinkedHashSet<>();
        for (AzureAgcTargets.SecretRef ref : targets.secrets()) {
            if (ref.namespace() == null || ref.namespace().isBlank()) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        CTX + " secrets[].namespace must be non-blank");
            }
            if (ref.secretName() == null || ref.secretName().isBlank()) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        CTX + " secrets[].secretName must be non-blank");
            }
            String key = ref.namespace().trim() + "/" + ref.secretName().trim();
            if (!seen.add(key)) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        "Duplicate secret ref: " + key);
            }
            if (!scopeNamespaces.contains(ref.namespace().trim())) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        "namespace '" + ref.namespace() + "' is not in the credential's scope.secretNamespaces");
            }
        }
        return targets.secrets();
    }

    private Map<String, Map<String, String>> groupByNamespace(
            List<AzureAgcTargets.SecretRef> secretRefs, String domain) {
        Map<String, Map<String, String>> byNamespace = new LinkedHashMap<>();
        for (AzureAgcTargets.SecretRef ref : secretRefs) {
            byNamespace
                    .computeIfAbsent(ref.namespace().trim(), k -> new LinkedHashMap<>())
                    .put(ref.secretName().trim(), domain);
        }
        return byNamespace;
    }

    private KubernetesSecretService.KubernetesAuthConfig buildAuthConfig(
            AzureAgcScope scope, AzureAuthSecret kvSecret,
            boolean isInCluster, String certificateXref) {
        if (isInCluster) {
            return KubernetesSecretService.KubernetesAuthConfig.forInCluster();
        }
        String clusterName = scope.clusterName();
        if (clusterName == null || clusterName.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credential missing clusterName for xref=" + certificateXref);
        }
        return kubernetesAuthService.resolveAzureAuthForAgc(
                clusterName,
                scope.tenantId(),
                scope.subscriptionId(),
                scope.resourceGroup(),
                kvSecret.clientId(),
                kvSecret.clientSecret());
    }

    private String resolveDomain(CertDeploymentMessage message, CertificateBundle bundle) {
        String fromMessage = CertificateIdentityUtils.normaliseDomain(message.getDomain());
        if (!fromMessage.isBlank()) {
            return fromMessage;
        }
        return CertificateIdentityUtils.extractPrimaryDomainFromPem(bundle.leafCertificate())
                .orElse("unknown");
    }

    private String toResultJson(String clusterName, String agcNamespace,
                                List<KubernetesSecretService.AppliedSecret> appliedSecrets) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            if (clusterName != null) root.put("clusterName", clusterName);
            if (agcNamespace != null) root.put("agcNamespace", agcNamespace);

            List<Map<String, Object>> applied = new ArrayList<>();
            for (KubernetesSecretService.AppliedSecret s : appliedSecrets) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("namespace", s.namespace());
                entry.put("secretName", s.secretName());
                if (s.resourceVersion() != null) entry.put("resourceVersion", s.resourceVersion());
                if (s.uid() != null) entry.put("uid", s.uid());
                applied.add(entry);
            }
            root.put("appliedSecrets", applied);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            log.warn("Azure AGC: failed to serialise result JSON — returning null: {}", e.getMessage());
            return null;
        }
    }

    private AzureAgcScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AzureAgcScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AzureAgcTargets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new AzureAgcTargets(List.of());
        }
        try {
            return objectMapper.readValue(json, AzureAgcTargets.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    "Failed to parse " + CTX + " targetsJson: " + e.getMessage(), e);
        }
    }

    private AzureAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AzureAuthSecret.empty();
        }
        return AzureScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    private String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }
}
