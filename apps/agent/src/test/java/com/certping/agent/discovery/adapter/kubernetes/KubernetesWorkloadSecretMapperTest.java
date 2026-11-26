// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesCertificateUsage;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1CronJob;
import io.kubernetes.client.openapi.models.V1CronJobSpec;
import io.kubernetes.client.openapi.models.V1DaemonSet;
import io.kubernetes.client.openapi.models.V1DaemonSetSpec;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1DeploymentSpec;
import io.kubernetes.client.openapi.models.V1EnvFromSource;
import io.kubernetes.client.openapi.models.V1EnvVar;
import io.kubernetes.client.openapi.models.V1EnvVarSource;
import io.kubernetes.client.openapi.models.V1Job;
import io.kubernetes.client.openapi.models.V1JobSpec;
import io.kubernetes.client.openapi.models.V1JobTemplateSpec;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1OwnerReference;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1PodTemplateSpec;
import io.kubernetes.client.openapi.models.V1ProjectedVolumeSource;
import io.kubernetes.client.openapi.models.V1SecretEnvSource;
import io.kubernetes.client.openapi.models.V1SecretKeySelector;
import io.kubernetes.client.openapi.models.V1SecretProjection;
import io.kubernetes.client.openapi.models.V1SecretVolumeSource;
import io.kubernetes.client.openapi.models.V1StatefulSet;
import io.kubernetes.client.openapi.models.V1StatefulSetSpec;
import io.kubernetes.client.openapi.models.V1Volume;
import io.kubernetes.client.openapi.models.V1VolumeProjection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link KubernetesWorkloadSecretMapper} — walks each workload kind's pod spec
 * (Deployment/StatefulSet/DaemonSet/Job/CronJob/standalone Pod), extracts every Secret
 * reference (volumes, projected sources, env, envFrom), and records the workload as an
 * affected user of that secret.
 */
class KubernetesWorkloadSecretMapperTest {

    private KubernetesWorkloadSecretMapper mapper;
    private KubernetesClusterInventory inventory;
    private Map<String, List<KubernetesCertificateUsage>> usagesBySecret;
    private Map<String, Set<String>> workloadsBySecret;

    @BeforeEach
    void setUp() {
        mapper = new KubernetesWorkloadSecretMapper();
        inventory = new KubernetesClusterInventory();
        usagesBySecret = new HashMap<>();
        workloadsBySecret = new HashMap<>();
    }

    // ── deployment / secret volume ─────────────────────────────────────────

    @Test
    void map_deploymentSecretVolume_recordsUsageAndWorkload() {
        V1Deployment deployment = new V1Deployment()
                .metadata(new V1ObjectMeta().namespace("prod").name("api").uid("uid-1"))
                .spec(new V1DeploymentSpec().template(
                        podTemplateWithSecretVolume("tls-secret")));
        inventory.deployments.add(deployment);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "prod", "tls-secret");
        assertThat(workloadsBySecret.get(key)).contains("prod/Deployment/api");
        assertThat(usagesBySecret.get(key)).singleElement().satisfies(usage -> {
            assertThat(usage.getKind()).isEqualTo("Deployment");
            assertThat(usage.getName()).isEqualTo("api");
            assertThat(usage.getApiVersion()).isEqualTo("apps/v1");
            assertThat(usage.getUsageType()).isEqualTo("WORKLOAD_SECRET_MOUNT");
            assertThat(usage.getConfidence()).isEqualTo("HIGH");
            assertThat(usage.getFieldPath()).contains("volumes[0].secret.secretName");
        });
    }

    // ── statefulset / projected secret ─────────────────────────────────────

    @Test
    void map_statefulSetProjectedSecret_recordsUsage() {
        V1Volume projectedVol = new V1Volume()
                .name("projected")
                .projected(new V1ProjectedVolumeSource().sources(List.of(
                        new V1VolumeProjection().secret(new V1SecretProjection().name("kv-secret")))));
        V1PodSpec podSpec = new V1PodSpec()
                .volumes(List.of(projectedVol))
                .containers(List.of(new V1Container().name("main")));
        V1StatefulSet ss = new V1StatefulSet()
                .metadata(new V1ObjectMeta().namespace("data").name("db"))
                .spec(new V1StatefulSetSpec().template(
                        new V1PodTemplateSpec().spec(podSpec)));
        inventory.statefulSets.add(ss);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "data", "kv-secret");
        assertThat(workloadsBySecret.get(key)).contains("data/StatefulSet/db");
        assertThat(usagesBySecret.get(key)).singleElement().satisfies(usage ->
                assertThat(usage.getFieldPath()).contains("projected.sources[0].secret.name"));
    }

    // ── daemonset / env valueFrom secretKeyRef ─────────────────────────────

    @Test
    void map_daemonSetEnvSecretKeyRef_recordsUsage() {
        V1Container container = new V1Container()
                .name("logger")
                .env(List.of(new V1EnvVar()
                        .name("API_KEY")
                        .valueFrom(new V1EnvVarSource().secretKeyRef(
                                new V1SecretKeySelector().name("api-key-secret").key("k")))));
        V1PodSpec podSpec = new V1PodSpec().containers(List.of(container));
        V1DaemonSet ds = new V1DaemonSet()
                .metadata(new V1ObjectMeta().namespace("kube-system").name("logger-agent"))
                .spec(new V1DaemonSetSpec().template(
                        new V1PodTemplateSpec().spec(podSpec)));
        inventory.daemonSets.add(ds);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "kube-system", "api-key-secret");
        assertThat(workloadsBySecret.get(key)).contains("kube-system/DaemonSet/logger-agent");
        assertThat(usagesBySecret.get(key)).singleElement().satisfies(usage ->
                assertThat(usage.getFieldPath()).contains("valueFrom.secretKeyRef.name"));
    }

    // ── job / envFrom secretRef ────────────────────────────────────────────

    @Test
    void map_jobEnvFromSecretRef_recordsUsage() {
        V1Container container = new V1Container()
                .name("worker")
                .envFrom(List.of(new V1EnvFromSource()
                        .secretRef(new V1SecretEnvSource().name("bulk-env-secret"))));
        V1Job job = new V1Job()
                .metadata(new V1ObjectMeta().namespace("batch").name("nightly-job"))
                .spec(new V1JobSpec().template(new V1PodTemplateSpec()
                        .spec(new V1PodSpec().containers(List.of(container)))));
        inventory.jobs.add(job);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "batch", "bulk-env-secret");
        assertThat(workloadsBySecret.get(key)).contains("batch/Job/nightly-job");
        assertThat(usagesBySecret.get(key)).singleElement().satisfies(usage ->
                assertThat(usage.getFieldPath()).contains("envFrom[0].secretRef.name"));
    }

    // ── cronjob deep nesting ───────────────────────────────────────────────

    @Test
    void map_cronJobDeepNestedTemplate_recordsUsageAtDeepPath() {
        V1PodSpec podSpec = new V1PodSpec()
                .volumes(List.of(new V1Volume().name("tls").secret(
                        new V1SecretVolumeSource().secretName("cron-tls"))))
                .containers(List.of(new V1Container().name("runner")));
        V1CronJob cronJob = new V1CronJob()
                .metadata(new V1ObjectMeta().namespace("scheduling").name("hourly"))
                .spec(new V1CronJobSpec().jobTemplate(new V1JobTemplateSpec()
                        .spec(new V1JobSpec().template(new V1PodTemplateSpec().spec(podSpec)))));
        inventory.cronJobs.add(cronJob);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "scheduling", "cron-tls");
        assertThat(workloadsBySecret.get(key)).contains("scheduling/CronJob/hourly");
        assertThat(usagesBySecret.get(key)).singleElement().satisfies(usage ->
                assertThat(usage.getFieldPath()).contains("spec.jobTemplate.spec.template.spec.volumes[0]"));
    }

    // ── standalone pod (no ownerReferences) ────────────────────────────────

    @Test
    void map_standalonePod_recordedAsUsage() {
        V1Pod pod = new V1Pod()
                .metadata(new V1ObjectMeta().namespace("misc").name("adhoc"))
                .spec(new V1PodSpec()
                        .volumes(List.of(new V1Volume().name("tls").secret(
                                new V1SecretVolumeSource().secretName("adhoc-tls"))))
                        .containers(List.of(new V1Container().name("c1"))));
        inventory.pods.add(pod);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "misc", "adhoc-tls");
        assertThat(workloadsBySecret.get(key)).contains("misc/Pod/adhoc");
    }

    @Test
    void map_podWithOwnerReferences_isSkipped() {
        // Pod owned by ReplicaSet — we already record the parent workload elsewhere,
        // so counting the pod would double-book the same underlying Deployment.
        V1Pod pod = new V1Pod()
                .metadata(new V1ObjectMeta().namespace("prod").name("api-abc-def")
                        .ownerReferences(List.of(
                                new V1OwnerReference().kind("ReplicaSet").name("api-abc").uid("rs-uid"))))
                .spec(new V1PodSpec()
                        .volumes(List.of(new V1Volume().name("tls").secret(
                                new V1SecretVolumeSource().secretName("api-tls"))))
                        .containers(List.of(new V1Container().name("c1"))));
        inventory.pods.add(pod);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        // Owned pod is skipped — no usage recorded.
        assertThat(usagesBySecret).isEmpty();
        assertThat(workloadsBySecret).isEmpty();
    }

    // ── null-guards / missing spec paths ───────────────────────────────────

    @Test
    void map_deploymentWithNullSpec_isSkipped() {
        V1Deployment d = new V1Deployment().metadata(new V1ObjectMeta().namespace("ns").name("n"));
        // .spec left null
        inventory.deployments.add(d);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        assertThat(usagesBySecret).isEmpty();
    }

    @Test
    void map_deploymentWithNullTemplate_isSkipped() {
        V1Deployment d = new V1Deployment()
                .metadata(new V1ObjectMeta().namespace("ns").name("n"))
                .spec(new V1DeploymentSpec()); // template null
        inventory.deployments.add(d);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        assertThat(usagesBySecret).isEmpty();
    }

    @Test
    void map_deploymentWithNullMetadata_isSkipped() {
        V1Deployment d = new V1Deployment()
                .spec(new V1DeploymentSpec().template(podTemplateWithSecretVolume("s")));
        // metadata null
        inventory.deployments.add(d);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        assertThat(usagesBySecret).isEmpty();
    }

    @Test
    void map_podSpecWithoutAnySecretReferences_recordsNothing() {
        V1Deployment d = new V1Deployment()
                .metadata(new V1ObjectMeta().namespace("ns").name("no-secrets"))
                .spec(new V1DeploymentSpec().template(new V1PodTemplateSpec()
                        .spec(new V1PodSpec()
                                .containers(List.of(new V1Container().name("c1"))))));
        inventory.deployments.add(d);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        assertThat(usagesBySecret).isEmpty();
    }

    @Test
    void map_volumeWithNullSecret_notCounted() {
        // Volume exists but no secret field — should be ignored, not NPE.
        V1Deployment d = new V1Deployment()
                .metadata(new V1ObjectMeta().namespace("ns").name("app"))
                .spec(new V1DeploymentSpec().template(new V1PodTemplateSpec()
                        .spec(new V1PodSpec()
                                .volumes(List.of(new V1Volume().name("configmap-vol"))) // no secret
                                .containers(List.of(new V1Container().name("c"))))));
        inventory.deployments.add(d);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        assertThat(usagesBySecret).isEmpty();
    }

    @Test
    void map_initContainerSecretRef_alsoTracked() {
        V1Container initC = new V1Container()
                .name("init")
                .env(List.of(new V1EnvVar()
                        .name("SETUP")
                        .valueFrom(new V1EnvVarSource().secretKeyRef(
                                new V1SecretKeySelector().name("init-secret").key("k")))));
        V1PodSpec podSpec = new V1PodSpec()
                .initContainers(List.of(initC))
                .containers(List.of(new V1Container().name("main")));
        V1Deployment d = new V1Deployment()
                .metadata(new V1ObjectMeta().namespace("ns").name("with-init"))
                .spec(new V1DeploymentSpec().template(new V1PodTemplateSpec().spec(podSpec)));
        inventory.deployments.add(d);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "ns", "init-secret");
        assertThat(usagesBySecret.get(key)).singleElement().satisfies(usage ->
                assertThat(usage.getFieldPath()).contains("initContainers"));
    }

    @Test
    void map_multipleWorkloadsShareSameSecret_bothTracked() {
        V1Deployment d1 = deploymentWithSecret("ns", "app-1", "shared-secret");
        V1Deployment d2 = deploymentWithSecret("ns", "app-2", "shared-secret");
        inventory.deployments.add(d1);
        inventory.deployments.add(d2);

        mapper.map(inventory, usagesBySecret, workloadsBySecret);

        String key = KubernetesParsedCertificate.usageLookupKey("Secret", "ns", "shared-secret");
        assertThat(workloadsBySecret.get(key))
                .containsExactlyInAnyOrder("ns/Deployment/app-1", "ns/Deployment/app-2");
        assertThat(usagesBySecret.get(key)).hasSize(2);
    }

    // ── containerNames helper (static, testable directly) ───────────────────

    @Test
    void containerNames_returnsSortedNames() {
        V1PodSpec spec = new V1PodSpec()
                .initContainers(List.of(new V1Container().name("init-b")))
                .containers(List.of(new V1Container().name("main-a"), new V1Container().name("main-c")));
        List<String> names = KubernetesWorkloadSecretMapper.containerNames(spec);
        assertThat(names).containsExactly("init-b", "main-a", "main-c");
    }

    @Test
    void containerNames_filtersNullNames() {
        V1PodSpec spec = new V1PodSpec()
                .containers(List.of(new V1Container(), new V1Container().name("named")));
        List<String> names = KubernetesWorkloadSecretMapper.containerNames(spec);
        assertThat(names).containsExactly("named");
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private static V1PodTemplateSpec podTemplateWithSecretVolume(String secretName) {
        return new V1PodTemplateSpec().spec(new V1PodSpec()
                .volumes(List.of(new V1Volume().name("tls").secret(
                        new V1SecretVolumeSource().secretName(secretName))))
                .containers(List.of(new V1Container().name("main"))));
    }

    private static V1Deployment deploymentWithSecret(String ns, String name, String secretName) {
        return new V1Deployment()
                .metadata(new V1ObjectMeta().namespace(ns).name(name))
                .spec(new V1DeploymentSpec().template(podTemplateWithSecretVolume(secretName)));
    }
}
