// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.DiscoveryFailedScope;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1CronJobList;
import io.kubernetes.client.openapi.models.V1DaemonSetList;
import io.kubernetes.client.openapi.models.V1DeploymentList;
import io.kubernetes.client.openapi.models.V1ListMeta;
import io.kubernetes.client.openapi.models.V1IngressList;
import io.kubernetes.client.openapi.models.V1JobList;
import io.kubernetes.client.openapi.models.V1NamespaceList;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1ReplicaSetList;
import io.kubernetes.client.openapi.models.V1SecretList;
import io.kubernetes.client.openapi.models.V1ServiceList;
import io.kubernetes.client.openapi.models.V1StatefulSetList;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
@Slf4j
class KubernetesInventoryClient {

    private static final int PAGE_LIMIT = 500;

    KubernetesClusterInventory collect(KubeApis.Core coreApi,
            KubeApis.Networking networkingApi,
            KubeApis.Apps appsApi,
            KubeApis.Batch batchApi,
            KubernetesDiscoveryScope scope) {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.addAll(resolveNamespaces(coreApi, scope));
        log.info("Collecting Kubernetes discovery inventory namespaceMode={} namespaceCount={} namespaceSample={}",
                scope.allNamespaces() ? "ALL_NAMESPACES" : "EXPLICIT",
                inventory.namespaces.size(),
                namespaceSample(inventory.namespaces));
        PermanentAgentException firstSecretFailure = null;
        for (String namespace : inventory.namespaces) {
            try {
                listCertificateSources(coreApi, namespace, inventory);
            } catch (PermanentAgentException e) {
                // One forbidden namespace must not hide the others: report it and keep going.
                if (firstSecretFailure == null) {
                    firstSecretFailure = e;
                }
                inventory.failedScopes.add(DiscoveryFailedScope.of(DiscoveryFailedScope.ScopeType.K8S_NAMESPACE,
                        namespace, e.getErrorCode(), e.getMessage()));
                continue;
            }
            listUsageResources(coreApi, networkingApi, appsApi, batchApi, namespace, inventory);
        }
        if (firstSecretFailure != null && inventory.failedScopes.size() >= inventory.namespaces.size()) {
            // Nothing could be read: fail the scan as before rather than report an empty partial result.
            throw firstSecretFailure;
        }
        log.info("Collected Kubernetes discovery inventory namespaces={} secrets={} ingresses={} services={} pods={} deployments={} replicaSets={} statefulSets={} daemonSets={} jobs={} cronJobs={} usageComplete={} unreadableResourceTypes={}",
                inventory.namespaces.size(), inventory.secrets.size(), inventory.ingresses.size(),
                inventory.services.size(), inventory.pods.size(), inventory.deployments.size(),
                inventory.replicaSets.size(), inventory.statefulSets.size(), inventory.daemonSets.size(),
                inventory.jobs.size(), inventory.cronJobs.size(), inventory.usageComplete(),
                inventory.unreadableResourceTypes.stream().sorted().toList());
        return inventory;
    }

    private List<String> resolveNamespaces(KubeApis.Core coreApi, KubernetesDiscoveryScope scope) {
        if (!scope.allNamespaces()) {
            return scope.explicitNamespaces();
        }
        try {
            java.util.ArrayList<String> namespaces = new java.util.ArrayList<>();
            String next = null;
            do {
                V1NamespaceList page = coreApi.listNamespaces(next, PAGE_LIMIT);
                if (page.getItems() != null) {
                    page.getItems().forEach(namespace -> {
                        if (namespace.getMetadata() != null && namespace.getMetadata().getName() != null) {
                            namespaces.add(namespace.getMetadata().getName());
                        }
                    });
                }
                next = page.getMetadata() != null ? page.getMetadata().getContinue() : null;
            } while (next != null && !next.isBlank());
            if (namespaces.isEmpty()) {
                throw new PermanentAgentException("DISCOVERY_K8S_NAMESPACE_LIST_EMPTY",
                        "Kubernetes discovery found no namespaces to scan");
            }
            namespaces.sort(String::compareTo);
            return namespaces;
        } catch (ApiException e) {
            log.error("Kubernetes namespace discovery failed operation=listNamespaces statusCode={} requiredRbac=\"list namespaces at cluster scope\"",
                    e.getCode());
            throw KubernetesDiscoveryErrorTranslator.translate(
                    "DISCOVERY_K8S_NAMESPACE_LIST_DENIED",
                    "list Kubernetes namespaces for discovery",
                    e);
        }
    }

    private void listCertificateSources(KubeApis.Core coreApi, String namespace, KubernetesClusterInventory inventory) {
        try {
            String next = null;
            do {
                V1SecretList page = coreApi.listSecrets(namespace, next, PAGE_LIMIT);
                if (page.getItems() != null) {
                    inventory.secrets.addAll(page.getItems());
                }
                next = page.getMetadata() != null ? page.getMetadata().getContinue() : null;
            } while (next != null && !next.isBlank());
        } catch (ApiException e) {
            log.error("Kubernetes certificate source inventory failed namespace={} resourceType=Secret statusCode={} requiredRbac=\"list secrets in namespace {}\"",
                    namespace, e.getCode(), namespace);
            throw KubernetesDiscoveryErrorTranslator.translate(
                    "DISCOVERY_K8S_SECRET_LIST_FAILED",
                    "list Kubernetes Secrets for discovery namespace=" + namespace,
                    e);
        }
    }

    private void listUsageResources(KubeApis.Core coreApi,
            KubeApis.Networking networkingApi,
            KubeApis.Apps appsApi,
            KubeApis.Batch batchApi,
            String namespace,
            KubernetesClusterInventory inventory) {
        collectUsage("Ingress", namespace, inventory, () -> {
            listAll(
                    token -> networkingApi.listIngresses(namespace, token, PAGE_LIMIT),
                    V1IngressList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.ingresses.addAll(page.getItems());
                    });
        });
        collectUsage("Service", namespace, inventory, () -> {
            listAll(
                    token -> coreApi.listServices(namespace, token, PAGE_LIMIT),
                    V1ServiceList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.services.addAll(page.getItems());
                    });
        });
        collectUsage("Pod", namespace, inventory, () -> {
            listAll(
                    token -> coreApi.listPods(namespace, token, PAGE_LIMIT),
                    V1PodList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.pods.addAll(page.getItems());
                    });
        });
        collectUsage("Deployment", namespace, inventory, () -> {
            listAll(
                    token -> appsApi.listDeployments(namespace, token, PAGE_LIMIT),
                    V1DeploymentList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.deployments.addAll(page.getItems());
                    });
        });
        collectUsage("ReplicaSet", namespace, inventory, () -> {
            listAll(
                    token -> appsApi.listReplicaSets(namespace, token, PAGE_LIMIT),
                    V1ReplicaSetList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.replicaSets.addAll(page.getItems());
                    });
        });
        collectUsage("StatefulSet", namespace, inventory, () -> {
            listAll(
                    token -> appsApi.listStatefulSets(namespace, token, PAGE_LIMIT),
                    V1StatefulSetList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.statefulSets.addAll(page.getItems());
                    });
        });
        collectUsage("DaemonSet", namespace, inventory, () -> {
            listAll(
                    token -> appsApi.listDaemonSets(namespace, token, PAGE_LIMIT),
                    V1DaemonSetList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.daemonSets.addAll(page.getItems());
                    });
        });
        collectUsage("Job", namespace, inventory, () -> {
            listAll(
                    token -> batchApi.listJobs(namespace, token, PAGE_LIMIT),
                    V1JobList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.jobs.addAll(page.getItems());
                    });
        });
        collectUsage("CronJob", namespace, inventory, () -> {
            listAll(
                    token -> batchApi.listCronJobs(namespace, token, PAGE_LIMIT),
                    V1CronJobList::getMetadata,
                    page -> {
                        if (page.getItems() != null) inventory.cronJobs.addAll(page.getItems());
                    });
        });
    }

    private <T> void listAll(PagedListCall<T> call,
            Function<T, V1ListMeta> metadata,
            PageConsumer<T> consumer) throws ApiException {
        String next = null;
        do {
            T page = call.execute(next);
            consumer.accept(page);
            V1ListMeta listMetadata = metadata.apply(page);
            next = listMetadata != null ? listMetadata.getContinue() : null;
        } while (next != null && !next.isBlank());
    }

    private void collectUsage(String resourceType, String namespace, KubernetesClusterInventory inventory, UsageListCall call) {
        try {
            call.execute();
        } catch (ApiException e) {
            log.warn("Kubernetes usage inventory is incomplete namespace={} resourceType={} statusCode={} requiredRbac=\"list {} resources in namespace {}\"",
                    namespace, resourceType, e.getCode(), resourceType, namespace);
            inventory.unreadableResourceTypes.add(resourceType);
            inventory.warnings.add("Unable to list " + resourceType + " resources for Kubernetes discovery; usage and impact are incomplete");
        }
    }

    private List<String> namespaceSample(List<String> namespaces) {
        int sampleSize = Math.min(namespaces.size(), 5);
        List<String> sample = namespaces.stream().limit(sampleSize).toList();
        if (namespaces.size() <= sampleSize) {
            return sample;
        }
        return java.util.stream.Stream.concat(sample.stream(), java.util.stream.Stream.of("..."))
                .toList();
    }

    @FunctionalInterface
    private interface UsageListCall {
        void execute() throws ApiException;
    }

    @FunctionalInterface
    private interface PagedListCall<T> {
        T execute(String continueToken) throws ApiException;
    }

    @FunctionalInterface
    private interface PageConsumer<T> {
        void accept(T page);
    }
}
