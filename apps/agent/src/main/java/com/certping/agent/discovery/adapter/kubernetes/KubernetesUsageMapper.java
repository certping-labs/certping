// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesCertificateImpact;
import com.certping.agent.model.message.KubernetesCertificateUsage;
import com.certping.agent.model.message.KubernetesWorkloadRef;
import io.kubernetes.client.openapi.models.V1Ingress;
import io.kubernetes.client.openapi.models.V1IngressBackend;
import io.kubernetes.client.openapi.models.V1HTTPIngressPath;
import io.kubernetes.client.openapi.models.V1IngressRule;
import io.kubernetes.client.openapi.models.V1IngressServiceBackend;
import io.kubernetes.client.openapi.models.V1IngressTLS;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Component
class KubernetesUsageMapper {

    Map<String, KubernetesMappedCertificateUsage> mapUsages(KubernetesClusterInventory inventory) {
        Map<String, List<KubernetesCertificateUsage>> usagesBySecret = new LinkedHashMap<>();
        Map<String, Set<String>> hostnamesBySecret = new LinkedHashMap<>();
        Map<String, Set<String>> servicesBySecret = new LinkedHashMap<>();
        Map<String, Set<String>> workloadsBySecret = new LinkedHashMap<>();
        Map<String, Set<String>> warningsBySecret = new LinkedHashMap<>();

        KubernetesServiceImpactResolver serviceIndex = new KubernetesServiceImpactResolver(
                inventory.services, inventory.pods, inventory.replicaSets, inventory.jobs);
        mapIngresses(inventory, serviceIndex, usagesBySecret, hostnamesBySecret, servicesBySecret, workloadsBySecret,
                warningsBySecret);
        new KubernetesWorkloadSecretMapper().map(inventory, usagesBySecret, workloadsBySecret);
        mapCustomResourceUsages(inventory, serviceIndex, usagesBySecret, hostnamesBySecret, servicesBySecret,
                workloadsBySecret, warningsBySecret);

        Map<String, KubernetesMappedCertificateUsage> result = new LinkedHashMap<>();
        Set<String> keys = new LinkedHashSet<>();
        keys.addAll(usagesBySecret.keySet());
        keys.addAll(hostnamesBySecret.keySet());
        keys.addAll(servicesBySecret.keySet());
        keys.addAll(workloadsBySecret.keySet());
        for (String key : keys) {
            List<KubernetesCertificateUsage> usages = usagesBySecret.getOrDefault(key, List.of()).stream()
                    .distinct()
                    .sorted(Comparator.comparing(this::usageSortKey))
                    .toList();
            KubernetesCertificateImpact impact = buildImpact(
                    hasTlsTerminationUsage(usages),
                    usages.stream().anyMatch(usage -> "WORKLOAD_SECRET_MOUNT".equals(usage.getUsageType())),
                    sortedList(hostnamesBySecret.getOrDefault(key, Set.of())),
                    sortedList(servicesBySecret.getOrDefault(key, Set.of())),
                    sortedList(workloadsBySecret.getOrDefault(key, Set.of())));
            result.put(key, new KubernetesMappedCertificateUsage(
                    usages,
                    impact,
                    warningsBySecret.getOrDefault(key, Set.of()).isEmpty(),
                    sortedList(warningsBySecret.getOrDefault(key, Set.of()))));
        }
        return result;
    }

    private void mapIngresses(KubernetesClusterInventory inventory,
            KubernetesServiceImpactResolver serviceIndex,
            Map<String, List<KubernetesCertificateUsage>> usagesBySecret,
            Map<String, Set<String>> hostnamesBySecret,
            Map<String, Set<String>> servicesBySecret,
            Map<String, Set<String>> workloadsBySecret,
            Map<String, Set<String>> warningsBySecret) {
        for (V1Ingress ingress : inventory.ingresses) {
            V1ObjectMeta metadata = ingress.getMetadata();
            if (metadata == null || ingress.getSpec() == null || ingress.getSpec().getTls() == null) {
                continue;
            }
            String namespace = metadata.getNamespace();
            for (int i = 0; i < ingress.getSpec().getTls().size(); i++) {
                V1IngressTLS tls = ingress.getSpec().getTls().get(i);
                if (tls.getSecretName() == null || tls.getSecretName().isBlank()) {
                    continue;
                }
                String secretKey = key("Secret", namespace, tls.getSecretName());
                List<String> hosts = tls.getHosts() == null ? List.of() : tls.getHosts();
                List<KubernetesBackendServiceRef> backends = ingressBackends(namespace, ingress, hosts);
                List<KubernetesWorkloadRef> workloads = serviceIndex.workloadsFor(backends);
                addAll(hostnamesBySecret, secretKey, hosts);
                addAll(servicesBySecret, secretKey, serviceNames(backends));
                addAll(workloadsBySecret, secretKey, workloadNames(workloads));
                markOutOfScopeBackendNamespaces(inventory, secretKey, backends, warningsBySecret);
                usagesBySecret.computeIfAbsent(secretKey, ignored -> new ArrayList<>()).add(
                        KubernetesCertificateUsage.builder()
                                .apiVersion("networking.k8s.io/v1")
                                .kind("Ingress")
                                .namespace(namespace)
                                .name(metadata.getName())
                                .uid(metadata.getUid())
                                .fieldPath("spec.tls[" + i + "].secretName")
                                .usageType("TLS_TERMINATION")
                                .hostnames(sortedList(new LinkedHashSet<>(hosts)))
                                .backendServices(backends)
                                .affectedWorkloads(workloads)
                                .confidence("HIGH")
                                .build());
            }
        }
    }

    private void mapCustomResourceUsages(KubernetesClusterInventory inventory,
            KubernetesServiceImpactResolver serviceIndex,
            Map<String, List<KubernetesCertificateUsage>> usagesBySecret,
            Map<String, Set<String>> hostnamesBySecret,
            Map<String, Set<String>> servicesBySecret,
            Map<String, Set<String>> workloadsBySecret,
            Map<String, Set<String>> warningsBySecret) {
        for (KubernetesCertificateUsageCandidate candidate : inventory.customResourceUsages) {
            String secretKey = key(
                    candidate.certificateSourceKind(),
                    candidate.certificateNamespace(),
                    candidate.certificateName());
            List<KubernetesWorkloadRef> workloads = serviceIndex.workloadsFor(candidate.backendServices());
            usagesBySecret.computeIfAbsent(secretKey, ignored -> new ArrayList<>()).add(
                    withResolvedBackends(candidate.usage(), candidate.backendServices(), workloads));
            addAll(hostnamesBySecret, secretKey, candidate.usage().getHostnames());
            addAll(servicesBySecret, secretKey, serviceNames(candidate.backendServices()));
            addAll(workloadsBySecret, secretKey, workloadNames(workloads));
            markOutOfScopeBackendNamespaces(inventory, secretKey, candidate.backendServices(), warningsBySecret);
        }
    }

    private KubernetesCertificateUsage withResolvedBackends(KubernetesCertificateUsage usage,
            List<KubernetesBackendServiceRef> backendServices,
            List<KubernetesWorkloadRef> affectedWorkloads) {
        return KubernetesCertificateUsage.builder()
                .apiVersion(usage.getApiVersion())
                .kind(usage.getKind())
                .namespace(usage.getNamespace())
                .name(usage.getName())
                .uid(usage.getUid())
                .fieldPath(usage.getFieldPath())
                .usageType(usage.getUsageType())
                .hostnames(usage.getHostnames())
                .backendServices(backendServices == null ? List.of() : backendServices)
                .affectedWorkloads(affectedWorkloads == null ? List.of() : affectedWorkloads)
                .confidence(usage.getConfidence())
                .build();
    }

    private List<KubernetesBackendServiceRef> ingressBackends(String namespace, V1Ingress ingress, List<String> tlsHosts) {
        List<KubernetesBackendServiceRef> backends = new ArrayList<>();
        boolean tlsHasHosts = tlsHosts != null && !tlsHosts.isEmpty();
        if (!tlsHasHosts && ingress.getSpec().getDefaultBackend() != null) {
            addIngressBackend(namespace, ingress.getSpec().getDefaultBackend(), backends);
        }
        if (ingress.getSpec().getRules() != null) {
            for (V1IngressRule rule : ingress.getSpec().getRules()) {
                if (tlsHasHosts && !tlsHosts.contains(rule.getHost())) {
                    continue;
                }
                if (rule.getHttp() == null || rule.getHttp().getPaths() == null) {
                    continue;
                }
                for (V1HTTPIngressPath path : rule.getHttp().getPaths()) {
                    addIngressBackend(namespace, path.getBackend(), backends);
                }
            }
        }
        return backends.stream().distinct().sorted(Comparator.comparing(this::serviceSortKey)).toList();
    }

    private void addIngressBackend(String namespace, V1IngressBackend backend, List<KubernetesBackendServiceRef> backends) {
        if (backend == null || backend.getService() == null) {
            return;
        }
        V1IngressServiceBackend service = backend.getService();
        backends.add(KubernetesBackendServiceRef.builder()
                .namespace(namespace)
                .name(service.getName())
                .portName(service.getPort() != null ? service.getPort().getName() : null)
                .portNumber(service.getPort() != null ? service.getPort().getNumber() : null)
                .build());
    }

    private void markOutOfScopeBackendNamespaces(KubernetesClusterInventory inventory,
            String secretKey,
            List<KubernetesBackendServiceRef> backendServices,
            Map<String, Set<String>> warningsBySecret) {
        if (backendServices == null || backendServices.isEmpty() || inventory.namespaces.isEmpty()) {
            return;
        }
        Set<String> scannedNamespaces = new LinkedHashSet<>(inventory.namespaces);
        for (KubernetesBackendServiceRef backendService : backendServices) {
            if (backendService.getNamespace() != null && !scannedNamespaces.contains(backendService.getNamespace())) {
                warningsBySecret.computeIfAbsent(secretKey, ignored -> new LinkedHashSet<>())
                        .add("Impact is incomplete because backend Service namespace "
                                + backendService.getNamespace()
                                + " was outside the Kubernetes discovery namespace scope");
            }
        }
    }

    private KubernetesCertificateImpact buildImpact(boolean externallyServed,
            boolean directlyMounted,
            List<String> hostnames,
            List<String> services,
            List<String> workloads) {
        String summary;
        String hostnameSummary = hostnames.isEmpty()
                ? "Kubernetes resources with unknown hostnames"
                : String.join(", ", hostnames);
        if (externallyServed && directlyMounted) {
            summary = "Expiry can break external TLS for " + hostnameSummary
                    + " and workloads mounting the certificate Secret.";
        } else if (externallyServed) {
            summary = "Expiry can break external TLS for " + hostnameSummary + ".";
        } else if (directlyMounted) {
            summary = "Expiry can break workloads mounting the certificate Secret.";
        } else {
            summary = "No Kubernetes usage references were found in readable resources.";
        }
        return KubernetesCertificateImpact.builder()
                .externallyServed(externallyServed)
                .directlyMountedByWorkloads(directlyMounted)
                .affectedHostnames(hostnames)
                .affectedServices(services)
                .affectedWorkloads(workloads)
                .summary(summary)
                .build();
    }

    private void addAll(Map<String, Set<String>> values, String key, List<String> additions) {
        if (additions == null || additions.isEmpty()) {
            return;
        }
        values.computeIfAbsent(key, ignored -> new LinkedHashSet<>()).addAll(additions);
    }

    private boolean hasTlsTerminationUsage(List<KubernetesCertificateUsage> usages) {
        return usages.stream().anyMatch(usage -> "TLS_TERMINATION".equals(usage.getUsageType()));
    }

    private List<String> serviceNames(List<KubernetesBackendServiceRef> services) {
        if (services == null) {
            return List.of();
        }
        return services.stream().map(service -> service.getNamespace() + "/" + service.getName()).toList();
    }

    private List<String> workloadNames(List<KubernetesWorkloadRef> workloads) {
        if (workloads == null) {
            return List.of();
        }
        return workloads.stream().map(this::workloadName).toList();
    }

    private String workloadName(KubernetesWorkloadRef workload) {
        return workload.getNamespace() + "/" + workload.getKind() + "/" + workload.getName();
    }

    private List<String> sortedList(Set<String> values) {
        return values.stream().filter(Objects::nonNull).sorted().toList();
    }

    private String key(String sourceKind, String namespace, String name) {
        return KubernetesParsedCertificate.usageLookupKey(sourceKind, namespace, name);
    }

    private String usageSortKey(KubernetesCertificateUsage usage) {
        return usage.getNamespace() + "/" + usage.getKind() + "/" + usage.getName() + "/" + usage.getFieldPath();
    }

    private String serviceSortKey(KubernetesBackendServiceRef service) {
        return service.getNamespace() + "/" + service.getName() + "/" + service.getPortName() + "/" + service.getPortNumber();
    }

}
