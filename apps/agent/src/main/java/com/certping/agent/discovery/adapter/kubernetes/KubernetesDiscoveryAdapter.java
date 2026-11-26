// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.deployment.adapter.kubernetes.KubernetesApiClientFactory;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesAuthService;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesSecretService;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesSecretService.KubernetesAuthConfig;
import com.certping.agent.discovery.DiscoveryAdapter;
import com.certping.agent.discovery.DiscoveryAdapterFor;
import com.certping.agent.discovery.DiscoveryResult;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.model.message.KubernetesCertificateData;
import com.certping.agent.model.message.KubernetesCertificateImpact;
import com.certping.agent.model.message.KubernetesCertificateUsage;
import tools.jackson.databind.ObjectMapper;
import io.kubernetes.client.openapi.ApiClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
@Component
@DiscoveryAdapterFor(TargetType.KUBERNETES_SECRETS)
@RequiredArgsConstructor
public class KubernetesDiscoveryAdapter implements DiscoveryAdapter {

    private static final Pattern RESOURCE_ID_SAFE_CLUSTER_NAME = Pattern.compile("[A-Za-z0-9._-]+");

    private final KubernetesAuthService authService;
    private final KubernetesApiClientFactory apiClientFactory;
    private final KubernetesInventoryClient inventoryClient;
    private final KubernetesCustomResourceScanner customResourceScanner;
    private final KubernetesCertificateParser certificateParser;
    private final KubernetesUsageMapper usageMapper;
    private final ObjectMapper objectMapper;

    @Override
    public List<DiscoveredCertEntry> discover(CertDiscoveryMessage message) {
        return discoverWithFailedScopes(message).certificates();
    }

    /**
     * Scans the cluster. A namespace whose TLS Secrets cannot be listed (for example RBAC forbids
     * it) is reported in {@code failedScopes} as K8S_NAMESPACE and the other namespaces are still
     * scanned. The scan fails when no namespace can be read, or when namespaces cannot be listed.
     */
    @Override
    public DiscoveryResult discoverWithFailedScopes(CertDiscoveryMessage message) {
        KubernetesDiscoveryScope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);
        log.info("Starting Kubernetes certificate discovery clusterName={} authProvider={} namespaceMode={} namespaceCount={}",
                scope.clusterName().trim(), scope.parsedAuthProvider(),
                scope.allNamespaces() ? "ALL_NAMESPACES" : "EXPLICIT",
                scope.explicitNamespaces().size());

        KubernetesAuthConfig authConfig = authService.resolveForDiscovery(
                scope.parsedAuthProvider(),
                scope.clusterName().trim(),
                message.getDeploymentCredHandle());
        ApiClient apiClient = apiClientFactory.buildApiClient(authConfig);

        KubernetesClusterInventory inventory = inventoryClient.collect(
                new KubeApis.Core(apiClient),
                new KubeApis.Networking(apiClient),
                new KubeApis.Apps(apiClient),
                new KubeApis.Batch(apiClient),
                scope);
        customResourceScanner.scan(
                new KubeApis.ApiExtensions(apiClient),
                new KubeApis.CustomObjects(apiClient),
                inventory,
                scope.clusterName().trim());

        List<KubernetesParsedCertificate> certificates = new ArrayList<>(
                certificateParser.parseTlsSecrets(scope.clusterName().trim(), inventory.secrets));
        certificates.addAll(inventory.inlineCertificates);
        Map<String, KubernetesMappedCertificateUsage> mappedUsages = usageMapper.mapUsages(inventory);

        List<DiscoveredCertEntry> entries = new ArrayList<>();
        for (KubernetesParsedCertificate certificate : certificates) {
            entries.add(toDiscoveredEntry(certificate, inventory, mappedUsages.get(certificate.usageLookupKey())));
        }
        entries.sort(Comparator.comparing(DiscoveredCertEntry::getResourceId));
        int usageCount = entries.stream()
                .map(DiscoveredCertEntry::getKubernetesData)
                .filter(java.util.Objects::nonNull)
                .mapToInt(data -> data.getUsages() == null ? 0 : data.getUsages().size())
                .sum();
        log.info("Kubernetes certificate discovery complete clusterName={} namespaces={} certificates={} usages={} usageComplete={} unreadableResourceTypeCount={}",
                scope.clusterName(), inventory.namespaces.size(), entries.size(), usageCount,
                inventory.usageComplete(), inventory.unreadableResourceTypes.size());
        if (!inventory.failedScopes.isEmpty()) {
            log.warn("Kubernetes certificate discovery partial clusterName={} failedNamespaces={}",
                    scope.clusterName(), inventory.failedScopes.size());
        }
        return new DiscoveryResult(entries, inventory.failedScopes);
    }

    private KubernetesDiscoveryScope parseScope(String credentialScopeJson) {
        if (credentialScopeJson == null || credentialScopeJson.isBlank()) {
            throw new PermanentAgentException("DISCOVERY_K8S_SCOPE_INVALID",
                    "Kubernetes discovery requires credentialScopeJson with authProvider and clusterName");
        }
        try {
            return KubernetesDiscoveryScope.fromJson(objectMapper.readTree(credentialScopeJson));
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("DISCOVERY_K8S_SCOPE_INVALID",
                    "Failed to parse Kubernetes discovery credentialScopeJson", e);
        }
    }

    private void validateScope(KubernetesDiscoveryScope scope) {
        scope.parsedAuthProvider();
        if (scope.clusterName() == null || scope.clusterName().isBlank()) {
            throw new PermanentAgentException("DISCOVERY_K8S_SCOPE_INVALID",
                    "Kubernetes discovery credentialScopeJson.clusterName is required");
        }
        String clusterName = scope.clusterName().trim();
        if (clusterName.length() > 253 || !RESOURCE_ID_SAFE_CLUSTER_NAME.matcher(clusterName).matches()) {
            throw new PermanentAgentException("DISCOVERY_K8S_SCOPE_INVALID",
                    "Kubernetes discovery credentialScopeJson.clusterName must be at most 253 characters and contain only letters, digits, dots, underscores, or hyphens");
        }
        if (!scope.allNamespaces() && scope.explicitNamespaces().isEmpty()) {
            throw new PermanentAgentException("DISCOVERY_K8S_SCOPE_INVALID",
                    "Kubernetes discovery credentialScopeJson.namespaces must be \"all_namespaces\" or contain at least one explicit namespace");
        }
        for (String namespace : scope.explicitNamespaces()) {
            KubernetesSecretService.validateDnsSubdomain(namespace, "namespace");
        }
    }

    private DiscoveredCertEntry toDiscoveredEntry(KubernetesParsedCertificate certificate,
            KubernetesClusterInventory inventory,
            KubernetesMappedCertificateUsage mappedUsage) {
        List<KubernetesCertificateUsage> usages = mappedUsage != null ? mappedUsage.usages() : List.of();
        KubernetesCertificateImpact impact = mappedUsage != null
                ? mappedUsage.impact()
                : defaultImpact(inventory.usageComplete());
        List<String> warnings = warningsFor(certificate, inventory, mappedUsage);
        KubernetesCertificateData kubernetesData = KubernetesCertificateData.builder()
                .clusterName(certificate.clusterName())
                .usageComplete(inventory.usageComplete())
                .impactComplete(inventory.usageComplete() && (mappedUsage == null || mappedUsage.impactComplete()))
                .unreadableResourceTypes(inventory.unreadableResourceTypes.stream().sorted().toList())
                .source(certificate.source())
                .usages(usages)
                .impact(impact)
                .warnings(warnings)
                .build();
        KubernetesCertificateMetadata metadata = certificateParser.metadataFor(certificate.certificate());
        return certificate.toEntry(kubernetesData, metadata, inUseBy(usages));
    }

    private KubernetesCertificateImpact defaultImpact(boolean usageComplete) {
        return KubernetesCertificateImpact.builder()
                .externallyServed(false)
                .directlyMountedByWorkloads(false)
                .affectedHostnames(List.of())
                .affectedServices(List.of())
                .affectedWorkloads(List.of())
                .summary(usageComplete
                        ? "No Kubernetes usage references were found in readable resources."
                        : "Usage and impact are incomplete because some Kubernetes resource types were unreadable.")
                .build();
    }

    private List<String> warningsFor(KubernetesParsedCertificate certificate, KubernetesClusterInventory inventory) {
        Set<String> warnings = new LinkedHashSet<>(certificate.warnings());
        warnings.addAll(inventory.warnings);
        if (!inventory.usageComplete()) {
            warnings.add("Do not treat an empty usage list as unused because usage inventory is incomplete");
        }
        return warnings.stream().sorted().toList();
    }

    private List<String> warningsFor(KubernetesParsedCertificate certificate,
            KubernetesClusterInventory inventory,
            KubernetesMappedCertificateUsage mappedUsage) {
        Set<String> warnings = new LinkedHashSet<>(warningsFor(certificate, inventory));
        if (mappedUsage != null) {
            warnings.addAll(mappedUsage.warnings());
        }
        return warnings.stream().sorted().toList();
    }

    private List<String> inUseBy(List<KubernetesCertificateUsage> usages) {
        return usages.stream()
                .map(usage -> usage.getNamespace() + "/" + usage.getKind() + "/" + usage.getName())
                .distinct()
                .sorted()
                .toList();
    }

}
