// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesWorkloadRef;
import io.kubernetes.client.openapi.models.V1Job;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1OwnerReference;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1ReplicaSet;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1ServiceSpec;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link KubernetesServiceImpactResolver} — given backend Service refs from a Route
 * or Ingress, walks pod selectors → owners to find the concrete Deployment / StatefulSet /
 * CronJob / Job that owns the pod. This lets discovery report "cert rotation will affect
 * these workloads" instead of just the raw service name.
 */
class KubernetesServiceImpactResolverTest {

    // ── empty inputs ────────────────────────────────────────────────────────

    @Test
    void workloadsFor_nullBackendRefs_returnsEmpty() {
        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(), List.of(), List.of(), List.of());
        assertThat(resolver.workloadsFor(null)).isEmpty();
    }

    @Test
    void workloadsFor_emptyBackendRefs_returnsEmpty() {
        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(), List.of(), List.of(), List.of());
        assertThat(resolver.workloadsFor(List.of())).isEmpty();
    }

    // ── service not found ──────────────────────────────────────────────────

    @Test
    void workloadsFor_serviceNotFound_returnsEmpty() {
        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(), List.of(), List.of(), List.of());
        List<KubernetesWorkloadRef> result = resolver.workloadsFor(
                List.of(KubernetesBackendServiceRef.builder()
                        .namespace("ns").name("missing").build()));
        assertThat(result).isEmpty();
    }

    // ── service without selector (headless) ────────────────────────────────

    @Test
    void workloadsFor_serviceWithoutSelector_returnsEmpty() {
        V1Service svc = svc("ns", "headless", null);
        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(), List.of(), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(
                List.of(ref("ns", "headless")));

        assertThat(result).isEmpty();
    }

    @Test
    void workloadsFor_serviceWithEmptySelector_returnsEmpty() {
        V1Service svc = svc("ns", "empty-sel", Map.of());
        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(), List.of(), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("ns", "empty-sel")));

        assertThat(result).isEmpty();
    }

    // ── pod matches service via selector → deployment (via ReplicaSet) ────

    @Test
    void workloadsFor_podOwnedByReplicaSetOwnedByDeployment_resolvesToDeployment() {
        V1Service svc = svc("prod", "api-svc", Map.of("app", "api"));
        V1Pod pod = podWithOwner("prod", "api-abc", Map.of("app", "api"),
                "ReplicaSet", "api-abc-rs", "rs-uid");
        V1ReplicaSet rs = new V1ReplicaSet().metadata(new V1ObjectMeta()
                .namespace("prod").name("api-abc-rs").uid("rs-uid")
                .ownerReferences(List.of(new V1OwnerReference()
                        .apiVersion("apps/v1").kind("Deployment").name("api").uid("dep-uid"))));

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(rs), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("prod", "api-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("Deployment");
            assertThat(w.getName()).isEqualTo("api");
            assertThat(w.getApiVersion()).isEqualTo("apps/v1");
        });
    }

    @Test
    void workloadsFor_podOwnedByOrphanReplicaSet_resolvesToReplicaSet() {
        // ReplicaSet with no Deployment owner → falls back to ReplicaSet as the workload.
        V1Service svc = svc("prod", "orphan-svc", Map.of("app", "orphan"));
        V1Pod pod = podWithOwner("prod", "orphan-abc", Map.of("app", "orphan"),
                "ReplicaSet", "orphan-rs", "rs-uid-2");
        V1ReplicaSet rs = new V1ReplicaSet().metadata(new V1ObjectMeta()
                .namespace("prod").name("orphan-rs").uid("rs-uid-2"));
                // No ownerReferences

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(rs), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("prod", "orphan-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("ReplicaSet");
            assertThat(w.getName()).isEqualTo("orphan-rs");
        });
    }

    // ── pod owned by Job → CronJob ─────────────────────────────────────────

    @Test
    void workloadsFor_podOwnedByJobOwnedByCronJob_resolvesToCronJob() {
        V1Service svc = svc("batch", "job-svc", Map.of("app", "batch"));
        V1Pod pod = podWithOwner("batch", "job-run-1", Map.of("app", "batch"),
                "Job", "hourly-1234", "job-uid");
        V1Job job = new V1Job().metadata(new V1ObjectMeta()
                .namespace("batch").name("hourly-1234").uid("job-uid")
                .ownerReferences(List.of(new V1OwnerReference()
                        .apiVersion("batch/v1").kind("CronJob").name("hourly").uid("cron-uid"))));

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(), List.of(job));

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("batch", "job-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("CronJob");
            assertThat(w.getName()).isEqualTo("hourly");
        });
    }

    @Test
    void workloadsFor_podOwnedByStandaloneJob_resolvesToJob() {
        V1Service svc = svc("batch", "job-svc", Map.of("app", "batch"));
        V1Pod pod = podWithOwner("batch", "job-run-1", Map.of("app", "batch"),
                "Job", "standalone", "job-uid-2");
        V1Job job = new V1Job().metadata(new V1ObjectMeta()
                .namespace("batch").name("standalone").uid("job-uid-2"));
                // No CronJob owner

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(), List.of(job));

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("batch", "job-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("Job");
            assertThat(w.getName()).isEqualTo("standalone");
        });
    }

    // ── pod owned by StatefulSet / DaemonSet / other → pass through ────────

    @Test
    void workloadsFor_podOwnedByStatefulSet_resolvesToStatefulSet() {
        V1Service svc = svc("data", "db-svc", Map.of("app", "db"));
        V1Pod pod = podWithOwner("data", "db-0", Map.of("app", "db"),
                "StatefulSet", "db", "ss-uid");

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("data", "db-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("StatefulSet");
            assertThat(w.getName()).isEqualTo("db");
        });
    }

    // ── pod without ownerReferences (standalone pod) ───────────────────────

    @Test
    void workloadsFor_standalonePod_resolvedAsPodWorkload() {
        // Pods with no ownerReferences fall through to being reported as Pod itself —
        // service selector matched, no owner chain to unwind.
        V1Service svc = svc("misc", "adhoc-svc", Map.of("app", "adhoc"));
        V1Pod pod = new V1Pod().metadata(new V1ObjectMeta()
                .namespace("misc").name("standalone-pod")
                .labels(Map.of("app", "adhoc")));

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("misc", "adhoc-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("Pod");
            assertThat(w.getName()).isEqualTo("standalone-pod");
        });
    }

    // ── pod in different namespace than service ────────────────────────────

    @Test
    void workloadsFor_podInDifferentNamespace_notMatched() {
        V1Service svc = svc("prod", "api-svc", Map.of("app", "api"));
        V1Pod pod = podWithOwner("dev", "api-abc", Map.of("app", "api"),
                "ReplicaSet", "api-rs", "rs-uid");

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("prod", "api-svc")));

        assertThat(result).isEmpty();
    }

    // ── pod with mismatched labels ─────────────────────────────────────────

    @Test
    void workloadsFor_podLabelsMismatch_notMatched() {
        V1Service svc = svc("prod", "api-svc", Map.of("app", "api", "tier", "backend"));
        V1Pod pod = podWithOwner("prod", "wrong-tier", Map.of("app", "api", "tier", "frontend"),
                "ReplicaSet", "rs", "rs-uid");

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("prod", "api-svc")));

        assertThat(result).isEmpty();
    }

    // ── multi-service dedup ────────────────────────────────────────────────

    @Test
    void workloadsFor_sameWorkloadHitTwiceViaTwoServices_dedupedToOne() {
        V1Service svc1 = svc("prod", "internal", Map.of("app", "api"));
        V1Service svc2 = svc("prod", "external", Map.of("app", "api"));
        V1Pod pod = podWithOwner("prod", "api-abc", Map.of("app", "api"),
                "ReplicaSet", "api-rs", "rs-uid");
        V1ReplicaSet rs = new V1ReplicaSet().metadata(new V1ObjectMeta()
                .namespace("prod").name("api-rs").uid("rs-uid")
                .ownerReferences(List.of(new V1OwnerReference()
                        .apiVersion("apps/v1").kind("Deployment").name("api"))));

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc1, svc2), List.of(pod), List.of(rs), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(
                List.of(ref("prod", "internal"), ref("prod", "external")));

        assertThat(result).hasSize(1);
    }

    // ── ReplicaSet / Job maps skip null metadata / uid ─────────────────────

    @Test
    void constructor_replicaSetWithoutUid_ignored() {
        V1Service svc = svc("prod", "api-svc", Map.of("app", "api"));
        V1Pod pod = podWithOwner("prod", "api-abc", Map.of("app", "api"),
                "ReplicaSet", "no-uid-rs", "missing-uid");
        // ReplicaSet with null uid metadata — resolver won't index it, falls back to RS-as-workload
        V1ReplicaSet rs = new V1ReplicaSet().metadata(new V1ObjectMeta()
                .namespace("prod").name("no-uid-rs"));
                // uid null → won't be indexed → replicaSetsByUid.get returns null

        KubernetesServiceImpactResolver resolver = new KubernetesServiceImpactResolver(
                List.of(svc), List.of(pod), List.of(rs), List.of());

        List<KubernetesWorkloadRef> result = resolver.workloadsFor(List.of(ref("prod", "api-svc")));

        assertThat(result).singleElement().satisfies(w -> {
            assertThat(w.getKind()).isEqualTo("ReplicaSet");
        });
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private static V1Service svc(String ns, String name, Map<String, String> selector) {
        V1Service s = new V1Service()
                .metadata(new V1ObjectMeta().namespace(ns).name(name));
        if (selector != null) {
            s.spec(new V1ServiceSpec().selector(selector));
        } else {
            s.spec(new V1ServiceSpec());
        }
        return s;
    }

    private static V1Pod podWithOwner(String ns, String name, Map<String, String> labels,
                                       String ownerKind, String ownerName, String ownerUid) {
        return new V1Pod()
                .metadata(new V1ObjectMeta().namespace(ns).name(name).labels(labels)
                        .ownerReferences(List.of(new V1OwnerReference()
                                .apiVersion("apps/v1").kind(ownerKind).name(ownerName).uid(ownerUid))))
                .spec(new V1PodSpec());
    }

    private static KubernetesBackendServiceRef ref(String ns, String name) {
        return KubernetesBackendServiceRef.builder().namespace(ns).name(name).build();
    }
}
