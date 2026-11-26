// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesCertificateUsage;
import com.certping.agent.model.message.KubernetesWorkloadRef;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1EnvFromSource;
import io.kubernetes.client.openapi.models.V1EnvVar;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1PodTemplateSpec;
import io.kubernetes.client.openapi.models.V1SecretKeySelector;
import io.kubernetes.client.openapi.models.V1SecretVolumeSource;
import io.kubernetes.client.openapi.models.V1Volume;
import io.kubernetes.client.openapi.models.V1VolumeProjection;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class KubernetesWorkloadSecretMapper {

    void map(KubernetesClusterInventory inventory,
            Map<String, List<KubernetesCertificateUsage>> usagesBySecret,
            Map<String, Set<String>> workloadsBySecret) {
        inventory.deployments.forEach(deployment -> mapPodTemplate(
                deployment.getMetadata(), "apps/v1", "Deployment",
                deployment.getSpec() != null ? deployment.getSpec().getTemplate() : null,
                "spec.template", usagesBySecret, workloadsBySecret));
        inventory.statefulSets.forEach(statefulSet -> mapPodTemplate(
                statefulSet.getMetadata(), "apps/v1", "StatefulSet",
                statefulSet.getSpec() != null ? statefulSet.getSpec().getTemplate() : null,
                "spec.template", usagesBySecret, workloadsBySecret));
        inventory.daemonSets.forEach(daemonSet -> mapPodTemplate(
                daemonSet.getMetadata(), "apps/v1", "DaemonSet",
                daemonSet.getSpec() != null ? daemonSet.getSpec().getTemplate() : null,
                "spec.template", usagesBySecret, workloadsBySecret));
        inventory.jobs.forEach(job -> mapPodTemplate(
                job.getMetadata(), "batch/v1", "Job",
                job.getSpec() != null ? job.getSpec().getTemplate() : null,
                "spec.template", usagesBySecret, workloadsBySecret));
        inventory.cronJobs.forEach(cronJob -> mapPodTemplate(
                cronJob.getMetadata(), "batch/v1", "CronJob",
                cronJob.getSpec() != null
                        && cronJob.getSpec().getJobTemplate() != null
                        && cronJob.getSpec().getJobTemplate().getSpec() != null
                        ? cronJob.getSpec().getJobTemplate().getSpec().getTemplate()
                        : null,
                "spec.jobTemplate.spec.template", usagesBySecret, workloadsBySecret));
        inventory.pods.stream()
                .filter(this::isStandalonePod)
                .forEach(pod -> mapPodSpec(
                        pod.getMetadata(), "v1", "Pod", pod.getSpec(), "spec", "pod",
                        usagesBySecret, workloadsBySecret));
    }

    private void mapPodTemplate(V1ObjectMeta metadata,
            String apiVersion,
            String kind,
            V1PodTemplateSpec template,
            String podTemplateFieldPath,
            Map<String, List<KubernetesCertificateUsage>> usagesBySecret,
            Map<String, Set<String>> workloadsBySecret) {
        if (metadata == null || template == null || template.getSpec() == null) {
            return;
        }
        mapPodSpec(metadata, apiVersion, kind, template.getSpec(), podTemplateFieldPath + ".spec",
                "pod template", usagesBySecret, workloadsBySecret);
    }

    private void mapPodSpec(V1ObjectMeta metadata,
            String apiVersion,
            String kind,
            V1PodSpec podSpec,
            String podSpecFieldPath,
            String referencePath,
            Map<String, List<KubernetesCertificateUsage>> usagesBySecret,
            Map<String, Set<String>> workloadsBySecret) {
        if (metadata == null || podSpec == null) {
            return;
        }
        String namespace = metadata.getNamespace();
        KubernetesWorkloadRef workload = KubernetesWorkloadRef.builder()
                .apiVersion(apiVersion)
                .kind(kind)
                .namespace(namespace)
                .name(metadata.getName())
                .containers(containerNames(podSpec))
                .referencePath(referencePath)
                .build();
        for (SecretReference reference : secretReferences(podSpec, podSpecFieldPath)) {
            String secretKey = KubernetesParsedCertificate.usageLookupKey(
                    "Secret", namespace, reference.secretName());
            workloadsBySecret.computeIfAbsent(secretKey, ignored -> new LinkedHashSet<>())
                    .add(workloadName(workload));
            usagesBySecret.computeIfAbsent(secretKey, ignored -> new ArrayList<>()).add(
                    KubernetesCertificateUsage.builder()
                            .apiVersion(apiVersion)
                            .kind(kind)
                            .namespace(namespace)
                            .name(metadata.getName())
                            .uid(metadata.getUid())
                            .fieldPath(reference.fieldPath())
                            .usageType("WORKLOAD_SECRET_MOUNT")
                            .hostnames(List.of())
                            .backendServices(List.of())
                            .affectedWorkloads(List.of(workload))
                            .confidence("HIGH")
                            .build());
        }
    }

    private boolean isStandalonePod(V1Pod pod) {
        return pod.getMetadata() != null
                && (pod.getMetadata().getOwnerReferences() == null
                        || pod.getMetadata().getOwnerReferences().isEmpty());
    }

    private List<SecretReference> secretReferences(V1PodSpec podSpec, String podSpecFieldPath) {
        List<SecretReference> references = new ArrayList<>();
        if (podSpec.getVolumes() != null) {
            for (int i = 0; i < podSpec.getVolumes().size(); i++) {
                V1Volume volume = podSpec.getVolumes().get(i);
                V1SecretVolumeSource secret = volume.getSecret();
                if (secret != null && secret.getSecretName() != null) {
                    references.add(new SecretReference(secret.getSecretName(),
                            podSpecFieldPath + ".volumes[" + i + "].secret.secretName"));
                }
                addProjectedSecretReferences(references, volume, podSpecFieldPath, i);
            }
        }
        addContainerSecretReferences(references, podSpec.getInitContainers(),
                podSpecFieldPath + ".initContainers");
        addContainerSecretReferences(references, podSpec.getContainers(),
                podSpecFieldPath + ".containers");
        return references;
    }

    private void addProjectedSecretReferences(List<SecretReference> references,
            V1Volume volume,
            String podSpecFieldPath,
            int volumeIndex) {
        if (volume.getProjected() == null || volume.getProjected().getSources() == null) {
            return;
        }
        for (int sourceIndex = 0; sourceIndex < volume.getProjected().getSources().size(); sourceIndex++) {
            V1VolumeProjection projection = volume.getProjected().getSources().get(sourceIndex);
            if (projection.getSecret() != null && projection.getSecret().getName() != null) {
                references.add(new SecretReference(projection.getSecret().getName(),
                        podSpecFieldPath + ".volumes[" + volumeIndex + "].projected.sources["
                                + sourceIndex + "].secret.name"));
            }
        }
    }

    private void addContainerSecretReferences(List<SecretReference> references,
            List<V1Container> containers,
            String containersFieldPath) {
        if (containers == null) {
            return;
        }
        for (int containerIndex = 0; containerIndex < containers.size(); containerIndex++) {
            V1Container container = containers.get(containerIndex);
            if (container.getEnv() != null) {
                for (int envIndex = 0; envIndex < container.getEnv().size(); envIndex++) {
                    V1EnvVar env = container.getEnv().get(envIndex);
                    V1SecretKeySelector secret = env.getValueFrom() != null
                            ? env.getValueFrom().getSecretKeyRef()
                            : null;
                    if (secret != null && secret.getName() != null) {
                        references.add(new SecretReference(secret.getName(),
                                containersFieldPath + "[" + containerIndex + "].env[" + envIndex
                                        + "].valueFrom.secretKeyRef.name"));
                    }
                }
            }
            if (container.getEnvFrom() != null) {
                for (int envIndex = 0; envIndex < container.getEnvFrom().size(); envIndex++) {
                    V1EnvFromSource envFrom = container.getEnvFrom().get(envIndex);
                    if (envFrom.getSecretRef() != null && envFrom.getSecretRef().getName() != null) {
                        references.add(new SecretReference(envFrom.getSecretRef().getName(),
                                containersFieldPath + "[" + containerIndex + "].envFrom[" + envIndex
                                        + "].secretRef.name"));
                    }
                }
            }
        }
    }

    static List<String> containerNames(V1PodSpec spec) {
        List<V1Container> containers = new ArrayList<>();
        if (spec.getInitContainers() != null) {
            containers.addAll(spec.getInitContainers());
        }
        if (spec.getContainers() != null) {
            containers.addAll(spec.getContainers());
        }
        return containers.stream()
                .map(V1Container::getName)
                .filter(Objects::nonNull)
                .sorted()
                .toList();
    }

    private String workloadName(KubernetesWorkloadRef workload) {
        return workload.getNamespace() + "/" + workload.getKind() + "/" + workload.getName();
    }

    private record SecretReference(String secretName, String fieldPath) {
    }
}
