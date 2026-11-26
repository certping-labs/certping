// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesWorkloadRef;
import io.kubernetes.client.openapi.models.V1Job;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1OwnerReference;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1ReplicaSet;
import io.kubernetes.client.openapi.models.V1Service;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class KubernetesServiceImpactResolver {

    private final List<V1Service> services;
    private final List<V1Pod> pods;
    private final Map<String, V1ReplicaSet> replicaSetsByUid = new LinkedHashMap<>();
    private final Map<String, V1Job> jobsByUid = new LinkedHashMap<>();

    KubernetesServiceImpactResolver(List<V1Service> services,
            List<V1Pod> pods,
            List<V1ReplicaSet> replicaSets,
            List<V1Job> jobs) {
        this.services = services;
        this.pods = pods;
        for (V1ReplicaSet replicaSet : replicaSets) {
            if (replicaSet.getMetadata() != null && replicaSet.getMetadata().getUid() != null) {
                replicaSetsByUid.put(replicaSet.getMetadata().getUid(), replicaSet);
            }
        }
        for (V1Job job : jobs) {
            if (job.getMetadata() != null && job.getMetadata().getUid() != null) {
                jobsByUid.put(job.getMetadata().getUid(), job);
            }
        }
    }

    List<KubernetesWorkloadRef> workloadsFor(List<KubernetesBackendServiceRef> backendRefs) {
        if (backendRefs == null || backendRefs.isEmpty()) {
            return List.of();
        }
        Set<KubernetesWorkloadRef> workloads = new LinkedHashSet<>();
        for (KubernetesBackendServiceRef backendRef : backendRefs) {
            V1Service service = findService(backendRef.getNamespace(), backendRef.getName());
            if (!hasUsableSelector(service)) {
                continue;
            }
            for (V1Pod pod : pods) {
                if (podMatchesService(pod, service)) {
                    workloads.add(resolvePodWorkload(pod));
                }
            }
        }
        return workloads.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(this::workloadName))
                .toList();
    }

    private V1Service findService(String namespace, String name) {
        return services.stream()
                .filter(service -> service.getMetadata() != null)
                .filter(service -> Objects.equals(namespace, service.getMetadata().getNamespace()))
                .filter(service -> Objects.equals(name, service.getMetadata().getName()))
                .findFirst()
                .orElse(null);
    }

    private boolean hasUsableSelector(V1Service service) {
        return service != null
                && service.getSpec() != null
                && service.getSpec().getSelector() != null
                && !service.getSpec().getSelector().isEmpty();
    }

    private boolean podMatchesService(V1Pod pod, V1Service service) {
        if (pod.getMetadata() == null || pod.getMetadata().getLabels() == null) {
            return false;
        }
        if (!Objects.equals(pod.getMetadata().getNamespace(), service.getMetadata().getNamespace())) {
            return false;
        }
        Map<String, String> labels = pod.getMetadata().getLabels();
        return service.getSpec().getSelector().entrySet().stream()
                .allMatch(entry -> Objects.equals(labels.get(entry.getKey()), entry.getValue()));
    }

    private KubernetesWorkloadRef resolvePodWorkload(V1Pod pod) {
        V1ObjectMeta metadata = pod.getMetadata();
        if (metadata == null) {
            return null;
        }
        if (metadata.getOwnerReferences() != null) {
            for (V1OwnerReference owner : orderedOwners(metadata.getOwnerReferences())) {
                if ("ReplicaSet".equals(owner.getKind())) {
                    V1OwnerReference deploymentOwner = deploymentOwner(replicaSetsByUid.get(owner.getUid()));
                    if (deploymentOwner != null) {
                        return workload("apps/v1", "Deployment", metadata.getNamespace(),
                                deploymentOwner.getName(), pod);
                    }
                    return workload("apps/v1", "ReplicaSet", metadata.getNamespace(), owner.getName(), pod);
                }
                if ("Job".equals(owner.getKind())) {
                    V1OwnerReference cronJobOwner = cronJobOwner(jobsByUid.get(owner.getUid()));
                    if (cronJobOwner != null) {
                        return workload("batch/v1", "CronJob", metadata.getNamespace(),
                                cronJobOwner.getName(), pod);
                    }
                    return workload("batch/v1", "Job", metadata.getNamespace(), owner.getName(), pod);
                }
                if (owner.getKind() != null) {
                    return workload(owner.getApiVersion(), owner.getKind(), metadata.getNamespace(),
                            owner.getName(), pod);
                }
            }
        }
        return workload("v1", "Pod", metadata.getNamespace(), metadata.getName(), pod);
    }

    private List<V1OwnerReference> orderedOwners(List<V1OwnerReference> owners) {
        return owners.stream()
                .sorted(Comparator.comparing(owner -> !Boolean.TRUE.equals(owner.getController())))
                .toList();
    }

    private V1OwnerReference deploymentOwner(V1ReplicaSet replicaSet) {
        if (replicaSet == null
                || replicaSet.getMetadata() == null
                || replicaSet.getMetadata().getOwnerReferences() == null) {
            return null;
        }
        return replicaSet.getMetadata().getOwnerReferences().stream()
                .filter(owner -> "Deployment".equals(owner.getKind()))
                .findFirst()
                .orElse(null);
    }

    private V1OwnerReference cronJobOwner(V1Job job) {
        if (job == null || job.getMetadata() == null || job.getMetadata().getOwnerReferences() == null) {
            return null;
        }
        return job.getMetadata().getOwnerReferences().stream()
                .filter(owner -> "CronJob".equals(owner.getKind()))
                .findFirst()
                .orElse(null);
    }

    private KubernetesWorkloadRef workload(String apiVersion,
            String kind,
            String namespace,
            String name,
            V1Pod pod) {
        return KubernetesWorkloadRef.builder()
                .apiVersion(apiVersion)
                .kind(kind)
                .namespace(namespace)
                .name(name)
                .containers(pod.getSpec() != null
                        ? KubernetesWorkloadSecretMapper.containerNames(pod.getSpec())
                        : List.of())
                .referencePath("service selector")
                .build();
    }

    private String workloadName(KubernetesWorkloadRef workload) {
        return workload.getNamespace() + "/" + workload.getKind() + "/" + workload.getName();
    }
}
