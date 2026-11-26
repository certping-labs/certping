// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.exception.PermanentAgentException;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1CronJob;
import io.kubernetes.client.openapi.models.V1CronJobList;
import io.kubernetes.client.openapi.models.V1DaemonSet;
import io.kubernetes.client.openapi.models.V1DaemonSetList;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1DeploymentList;
import io.kubernetes.client.openapi.models.V1Ingress;
import io.kubernetes.client.openapi.models.V1IngressList;
import io.kubernetes.client.openapi.models.V1Job;
import io.kubernetes.client.openapi.models.V1JobList;
import io.kubernetes.client.openapi.models.V1ListMeta;
import io.kubernetes.client.openapi.models.V1Namespace;
import io.kubernetes.client.openapi.models.V1NamespaceList;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1ReplicaSet;
import io.kubernetes.client.openapi.models.V1ReplicaSetList;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.openapi.models.V1SecretList;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1ServiceList;
import io.kubernetes.client.openapi.models.V1StatefulSet;
import io.kubernetes.client.openapi.models.V1StatefulSetList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link KubernetesInventoryClient} — the fan-out lister that walks the
 * cluster for TLS Secrets and usage resources (Ingress/Service/Pod/Deployment/etc.).
 *
 * <p>The class is package-private; tests live in the same package. All API
 * calls are mocked; no real cluster is contacted.
 */
class KubernetesInventoryClientTest {

    private KubernetesInventoryClient client;
    private KubeApis.Core coreApi;
    private KubeApis.Networking networkingApi;
    private KubeApis.Apps appsApi;
    private KubeApis.Batch batchApi;

    @BeforeEach
    void setUp() {
        client = new KubernetesInventoryClient();
        coreApi = mock(KubeApis.Core.class);
        networkingApi = mock(KubeApis.Networking.class);
        appsApi = mock(KubeApis.Apps.class);
        batchApi = mock(KubeApis.Batch.class);
    }

    // ── resolveNamespaces via explicit scope ───────────────────────────────

    @Test
    void collect_explicitNamespaces_skipsListNamespace() throws Exception {
        // Explicit namespaces mode → never call coreApi.listNamespace.
        // Each namespace still walked for secrets + usage, but with empty pages.
        stubEmptyUsagePages();
        stubEmptySecretPage();

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a", "ns-b"), false);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        assertThat(inv.namespaces).containsExactly("ns-a", "ns-b");
        verify(coreApi, times(0)).listNamespaces(any(), any());
    }

    // ── resolveNamespaces via all-namespaces + pagination ──────────────────

    @Test
    void collect_allNamespaces_paginatesAndSortsResults() throws Exception {
        V1NamespaceList page1 = new V1NamespaceList();
        page1.setItems(List.of(namespaceItem("zeta"), namespaceItem("alpha")));
        V1ListMeta meta1 = new V1ListMeta();
        meta1.setContinue("token-1");
        page1.setMetadata(meta1);

        V1NamespaceList page2 = new V1NamespaceList();
        page2.setItems(List.of(namespaceItem("mu")));
        page2.setMetadata(new V1ListMeta());

        when(coreApi.listNamespaces(any(), any())).thenReturn(page1, page2);
        stubEmptyUsagePages();
        stubEmptySecretPage();

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of(), true);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        // Sorted after pagination: alpha, mu, zeta.
        assertThat(inv.namespaces).containsExactly("alpha", "mu", "zeta");
        verify(coreApi, times(2)).listNamespaces(any(), any());
    }

    @Test
    void collect_allNamespaces_emptyResult_throwsPermanent() throws Exception {
        V1NamespaceList empty = new V1NamespaceList();
        empty.setItems(List.of());
        empty.setMetadata(new V1ListMeta());
        when(coreApi.listNamespaces(any(), any())).thenReturn(empty);

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of(), true);

        assertThatThrownBy(() -> client.collect(coreApi, networkingApi, appsApi, batchApi, scope))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_NAMESPACE_LIST_EMPTY"));
    }

    @Test
    void collect_allNamespaces_apiExceptionDenied_throwsTranslatedException() throws Exception {
        when(coreApi.listNamespaces(any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of(), true);

        assertThatThrownBy(() -> client.collect(coreApi, networkingApi, appsApi, batchApi, scope))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void collect_allNamespaces_skipsMissingMetadataOrName() throws Exception {
        V1NamespaceList page = new V1NamespaceList();
        // one anonymous (no metadata), one nameless (metadata but no name), one valid.
        V1Namespace anon = new V1Namespace();
        V1Namespace nameless = new V1Namespace();
        nameless.setMetadata(new V1ObjectMeta());
        page.setItems(List.of(anon, nameless, namespaceItem("real")));
        page.setMetadata(new V1ListMeta());
        when(coreApi.listNamespaces(any(), any())).thenReturn(page);
        stubEmptyUsagePages();
        stubEmptySecretPage();

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of(), true);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        // Only "real" survives the null-guards.
        assertThat(inv.namespaces).containsExactly("real");
    }

    // ── listCertificateSources (Secret) ────────────────────────────────────

    @Test
    void collect_secretListWithMultiplePages_gathersAllSecrets() throws Exception {
        V1SecretList secretPage1 = new V1SecretList();
        V1Secret s1 = new V1Secret();
        s1.setMetadata(new V1ObjectMeta().name("s1").namespace("ns-a"));
        secretPage1.setItems(List.of(s1));
        V1ListMeta meta = new V1ListMeta();
        meta.setContinue("cont");
        secretPage1.setMetadata(meta);

        V1SecretList secretPage2 = new V1SecretList();
        V1Secret s2 = new V1Secret();
        s2.setMetadata(new V1ObjectMeta().name("s2").namespace("ns-a"));
        secretPage2.setItems(List.of(s2));
        secretPage2.setMetadata(new V1ListMeta());

        when(coreApi.listSecrets(eq("ns-a"), any(), any()))
                .thenReturn(secretPage1, secretPage2);

        stubEmptyUsagePages();

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a"), false);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        assertThat(inv.secrets).hasSize(2);
        assertThat(inv.secrets).extracting(s -> s.getMetadata().getName())
                .containsExactlyInAnyOrder("s1", "s2");
    }

    @Test
    void collect_secretListFails_throwsTranslated() throws Exception {
        when(coreApi.listSecrets(eq("ns-a"), any(), any()))
                .thenThrow(new ApiException(403, "denied"));

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a"), false);

        assertThatThrownBy(() -> client.collect(coreApi, networkingApi, appsApi, batchApi, scope))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void collect_oneNamespaceForbidden_reportsFailedScopeAndScansTheOthers() throws Exception {
        stubEmptyUsagePages();
        when(coreApi.listSecrets(eq("ns-a"), any(), any()))
                .thenThrow(new ApiException(403, "denied"));
        V1SecretList page = new V1SecretList();
        V1Secret s = new V1Secret();
        s.setMetadata(new V1ObjectMeta().name("tls-b").namespace("ns-b"));
        page.setItems(List.of(s));
        page.setMetadata(new V1ListMeta());
        when(coreApi.listSecrets(eq("ns-b"), any(), any())).thenReturn(page);

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a", "ns-b"), false);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        assertThat(inv.secrets).extracting(x -> x.getMetadata().getName()).containsExactly("tls-b");
        assertThat(inv.failedScopes).singleElement().satisfies(f -> {
            assertThat(f.getScopeType()).isEqualTo(
                    com.certping.agent.model.message.DiscoveryFailedScope.ScopeType.K8S_NAMESPACE);
            assertThat(f.getScopeId()).isEqualTo("ns-a");
            assertThat(f.getErrorCode()).isEqualTo("DISCOVERY_K8S_SECRET_LIST_FAILED");
        });
    }

    // ── listUsageResources: individual resource types are collectUsage-guarded ─

    @Test
    void collect_ingressListFails_marksUnreadableButContinues() throws Exception {
        stubEmptySecretPage();
        when(networkingApi.listIngresses(eq("ns-a"), any(), any()))
                .thenThrow(new ApiException(403, "denied"));
        // All other usage resources return empty
        stubEmptyForNonIngressUsage();

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a"), false);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        // Ingress fails, others succeed → unreadable list includes only Ingress.
        assertThat(inv.unreadableResourceTypes).contains("Ingress");
        assertThat(inv.usageComplete()).isFalse();
        assertThat(inv.warnings).anyMatch(w -> w.contains("Ingress"));
    }

    @Test
    void collect_allUsageResourcesEmpty_usageCompleteTrue() throws Exception {
        stubEmptySecretPage();
        stubEmptyUsagePages();

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a"), false);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        assertThat(inv.usageComplete()).isTrue();
        assertThat(inv.unreadableResourceTypes).isEmpty();
    }

    @Test
    void collect_allUsagesReturnItems_populatesInventory() throws Exception {
        stubEmptySecretPage();

        V1IngressList ingressList = new V1IngressList();
        V1Ingress ingress = new V1Ingress();
        ingress.setMetadata(new V1ObjectMeta().name("ing1"));
        ingressList.setItems(List.of(ingress));
        ingressList.setMetadata(new V1ListMeta());
        when(networkingApi.listIngresses(any(), any(), any())).thenReturn(ingressList);

        V1ServiceList svcList = new V1ServiceList();
        V1Service svc = new V1Service();
        svc.setMetadata(new V1ObjectMeta().name("svc1"));
        svcList.setItems(List.of(svc));
        svcList.setMetadata(new V1ListMeta());
        when(coreApi.listServices(any(), any(), any())).thenReturn(svcList);

        V1PodList podList = new V1PodList();
        V1Pod pod = new V1Pod();
        pod.setMetadata(new V1ObjectMeta().name("p1"));
        podList.setItems(List.of(pod));
        podList.setMetadata(new V1ListMeta());
        when(coreApi.listPods(any(), any(), any())).thenReturn(podList);

        V1DeploymentList depList = new V1DeploymentList();
        V1Deployment dep = new V1Deployment();
        dep.setMetadata(new V1ObjectMeta().name("d1"));
        depList.setItems(List.of(dep));
        depList.setMetadata(new V1ListMeta());
        when(appsApi.listDeployments(any(), any(), any())).thenReturn(depList);

        V1ReplicaSetList rsList = new V1ReplicaSetList();
        V1ReplicaSet rs = new V1ReplicaSet();
        rs.setMetadata(new V1ObjectMeta().name("rs1"));
        rsList.setItems(List.of(rs));
        rsList.setMetadata(new V1ListMeta());
        when(appsApi.listReplicaSets(any(), any(), any())).thenReturn(rsList);

        V1StatefulSetList ssList = new V1StatefulSetList();
        V1StatefulSet ss = new V1StatefulSet();
        ss.setMetadata(new V1ObjectMeta().name("ss1"));
        ssList.setItems(List.of(ss));
        ssList.setMetadata(new V1ListMeta());
        when(appsApi.listStatefulSets(any(), any(), any())).thenReturn(ssList);

        V1DaemonSetList dsList = new V1DaemonSetList();
        V1DaemonSet ds = new V1DaemonSet();
        ds.setMetadata(new V1ObjectMeta().name("ds1"));
        dsList.setItems(List.of(ds));
        dsList.setMetadata(new V1ListMeta());
        when(appsApi.listDaemonSets(any(), any(), any())).thenReturn(dsList);

        V1JobList jobList = new V1JobList();
        V1Job job = new V1Job();
        job.setMetadata(new V1ObjectMeta().name("j1"));
        jobList.setItems(List.of(job));
        jobList.setMetadata(new V1ListMeta());
        when(batchApi.listJobs(any(), any(), any())).thenReturn(jobList);

        V1CronJobList cronList = new V1CronJobList();
        V1CronJob cron = new V1CronJob();
        cron.setMetadata(new V1ObjectMeta().name("cj1"));
        cronList.setItems(List.of(cron));
        cronList.setMetadata(new V1ListMeta());
        when(batchApi.listCronJobs(any(), any(), any())).thenReturn(cronList);

        KubernetesDiscoveryScope scope = new KubernetesDiscoveryScope(
                "SA_TOKEN", "c1", List.of("ns-a"), false);

        KubernetesClusterInventory inv = client.collect(coreApi, networkingApi, appsApi, batchApi, scope);

        // Every usage bucket populated
        assertThat(inv.ingresses).hasSize(1);
        assertThat(inv.services).hasSize(1);
        assertThat(inv.pods).hasSize(1);
        assertThat(inv.deployments).hasSize(1);
        assertThat(inv.replicaSets).hasSize(1);
        assertThat(inv.statefulSets).hasSize(1);
        assertThat(inv.daemonSets).hasSize(1);
        assertThat(inv.jobs).hasSize(1);
        assertThat(inv.cronJobs).hasSize(1);
        assertThat(inv.usageComplete()).isTrue();
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private static V1Namespace namespaceItem(String name) {
        V1Namespace n = new V1Namespace();
        V1ObjectMeta meta = new V1ObjectMeta();
        meta.setName(name);
        n.setMetadata(meta);
        return n;
    }

    private void stubEmptySecretPage() throws Exception {
        V1SecretList empty = new V1SecretList();
        empty.setItems(List.of());
        empty.setMetadata(new V1ListMeta());
        when(coreApi.listSecrets(any(), any(), any())).thenReturn(empty);
    }

    private void stubEmptyUsagePages() throws Exception {
        V1IngressList ing = new V1IngressList();
        ing.setItems(List.of()); ing.setMetadata(new V1ListMeta());
        when(networkingApi.listIngresses(any(), any(), any())).thenReturn(ing);

        V1ServiceList svc = new V1ServiceList();
        svc.setItems(List.of()); svc.setMetadata(new V1ListMeta());
        when(coreApi.listServices(any(), any(), any())).thenReturn(svc);

        V1PodList pod = new V1PodList();
        pod.setItems(List.of()); pod.setMetadata(new V1ListMeta());
        when(coreApi.listPods(any(), any(), any())).thenReturn(pod);

        V1DeploymentList dep = new V1DeploymentList();
        dep.setItems(List.of()); dep.setMetadata(new V1ListMeta());
        when(appsApi.listDeployments(any(), any(), any())).thenReturn(dep);

        V1ReplicaSetList rs = new V1ReplicaSetList();
        rs.setItems(List.of()); rs.setMetadata(new V1ListMeta());
        when(appsApi.listReplicaSets(any(), any(), any())).thenReturn(rs);

        V1StatefulSetList ss = new V1StatefulSetList();
        ss.setItems(List.of()); ss.setMetadata(new V1ListMeta());
        when(appsApi.listStatefulSets(any(), any(), any())).thenReturn(ss);

        V1DaemonSetList ds = new V1DaemonSetList();
        ds.setItems(List.of()); ds.setMetadata(new V1ListMeta());
        when(appsApi.listDaemonSets(any(), any(), any())).thenReturn(ds);

        V1JobList job = new V1JobList();
        job.setItems(List.of()); job.setMetadata(new V1ListMeta());
        when(batchApi.listJobs(any(), any(), any())).thenReturn(job);

        V1CronJobList cron = new V1CronJobList();
        cron.setItems(List.of()); cron.setMetadata(new V1ListMeta());
        when(batchApi.listCronJobs(any(), any(), any())).thenReturn(cron);
    }

    private void stubEmptyForNonIngressUsage() throws Exception {
        // Same as stubEmptyUsagePages but skips the ingress stub (caller sets one that throws).
        V1ServiceList svc = new V1ServiceList();
        svc.setItems(List.of()); svc.setMetadata(new V1ListMeta());
        when(coreApi.listServices(any(), any(), any())).thenReturn(svc);

        V1PodList pod = new V1PodList();
        pod.setItems(List.of()); pod.setMetadata(new V1ListMeta());
        when(coreApi.listPods(any(), any(), any())).thenReturn(pod);

        V1DeploymentList dep = new V1DeploymentList();
        dep.setItems(List.of()); dep.setMetadata(new V1ListMeta());
        when(appsApi.listDeployments(any(), any(), any())).thenReturn(dep);

        V1ReplicaSetList rs = new V1ReplicaSetList();
        rs.setItems(List.of()); rs.setMetadata(new V1ListMeta());
        when(appsApi.listReplicaSets(any(), any(), any())).thenReturn(rs);

        V1StatefulSetList ss = new V1StatefulSetList();
        ss.setItems(List.of()); ss.setMetadata(new V1ListMeta());
        when(appsApi.listStatefulSets(any(), any(), any())).thenReturn(ss);

        V1DaemonSetList ds = new V1DaemonSetList();
        ds.setItems(List.of()); ds.setMetadata(new V1ListMeta());
        when(appsApi.listDaemonSets(any(), any(), any())).thenReturn(ds);

        V1JobList job = new V1JobList();
        job.setItems(List.of()); job.setMetadata(new V1ListMeta());
        when(batchApi.listJobs(any(), any(), any())).thenReturn(job);

        V1CronJobList cron = new V1CronJobList();
        cron.setItems(List.of()); cron.setMetadata(new V1ListMeta());
        when(batchApi.listCronJobs(any(), any(), any())).thenReturn(cron);
    }
}
