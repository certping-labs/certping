// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesCertificateUsage;
import io.kubernetes.client.openapi.models.V1HTTPIngressPath;
import io.kubernetes.client.openapi.models.V1HTTPIngressRuleValue;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1EnvVar;
import io.kubernetes.client.openapi.models.V1EnvVarSource;
import io.kubernetes.client.openapi.models.V1Ingress;
import io.kubernetes.client.openapi.models.V1IngressBackend;
import io.kubernetes.client.openapi.models.V1IngressRule;
import io.kubernetes.client.openapi.models.V1IngressServiceBackend;
import io.kubernetes.client.openapi.models.V1IngressSpec;
import io.kubernetes.client.openapi.models.V1IngressTLS;
import io.kubernetes.client.openapi.models.V1Job;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1OwnerReference;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1SecretKeySelector;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1ServiceBackendPort;
import io.kubernetes.client.openapi.models.V1ServiceSpec;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KubernetesUsageMapperTest {

    private final KubernetesUsageMapper mapper = new KubernetesUsageMapper();

    @Test
    void mapUsages_emptyServiceSelector_doesNotMatchEveryPod() {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.services.add(service("frontend", "api", Map.of()));
        inventory.pods.add(pod("frontend", "unrelated", Map.of("app", "other"), List.of()));
        inventory.customResourceUsages.add(usageCandidate("frontend", "api-tls", "api"));

        KubernetesMappedCertificateUsage mapped = mapper.mapUsages(inventory).get(secretKey("api-tls"));

        assertThat(mapped).isNotNull();
        assertThat(mapped.usages()).singleElement()
                .satisfies(usage -> assertThat(usage.getAffectedWorkloads()).isEmpty());
        assertThat(mapped.impact().getAffectedWorkloads()).isEmpty();
    }

    @Test
    void mapUsages_tlsTerminationWithoutHostnames_isExternallyServedWithUnknownHostnames() {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.customResourceUsages.add(usageCandidate("frontend", "api-tls", "api", List.of()));

        KubernetesMappedCertificateUsage mapped = mapper.mapUsages(inventory).get(secretKey("api-tls"));

        assertThat(mapped.impact().isExternallyServed()).isTrue();
        assertThat(mapped.impact().getAffectedHostnames()).isEmpty();
        assertThat(mapped.impact().getSummary())
                .isEqualTo("Expiry can break external TLS for Kubernetes resources with unknown hostnames.");
    }

    @Test
    void mapUsages_ingressTlsHosts_resolvesOnlyMatchingRuleBackends() {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.ingresses.add(new V1Ingress()
                .metadata(new V1ObjectMeta().namespace("frontend").name("edge").uid("ingress-uid"))
                .spec(new V1IngressSpec()
                        .tls(List.of(
                                new V1IngressTLS().secretName("api-tls").hosts(List.of("api.example.com")),
                                new V1IngressTLS().secretName("admin-tls").hosts(List.of("admin.example.com"))))
                        .rules(List.of(
                                ingressRule("api.example.com", "api-service"),
                                ingressRule("admin.example.com", "admin-service")))));

        Map<String, KubernetesMappedCertificateUsage> mapped = mapper.mapUsages(inventory);

        assertThat(mapped.get(secretKey("api-tls")).impact().getAffectedServices())
                .containsExactly("frontend/api-service");
        assertThat(mapped.get(secretKey("admin-tls")).impact().getAffectedServices())
                .containsExactly("frontend/admin-service");
        assertThat(mapped.get(secretKey("api-tls")).usages()).singleElement()
                .satisfies(usage -> assertThat(usage.getBackendServices()).singleElement()
                        .satisfies(service -> assertThat(service.getName()).isEqualTo("api-service")));
    }

    @Test
    void mapUsages_crossNamespaceBackendOutsideScope_marksImpactIncomplete() {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("gateway-system");
        inventory.customResourceUsages.add(usageCandidate("gateway-system", "shared-tls", "frontend", "api", List.of()));

        KubernetesMappedCertificateUsage mapped = mapper.mapUsages(inventory)
                .get(KubernetesParsedCertificate.usageLookupKey("Secret", "gateway-system", "shared-tls"));

        assertThat(mapped.impactComplete()).isFalse();
        assertThat(mapped.warnings()).containsExactly(
                "Impact is incomplete because backend Service namespace frontend was outside the Kubernetes discovery namespace scope");
    }

    @Test
    void mapUsages_jobOwnedByCronJob_resolvesCronJobImpact() {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.services.add(service("frontend", "batch-api", Map.of("job", "report")));
        inventory.jobs.add(new V1Job().metadata(new V1ObjectMeta()
                .namespace("frontend")
                .name("report-123")
                .uid("job-uid")
                .ownerReferences(List.of(owner("batch/v1", "CronJob", "report", "cron-uid", true)))));
        inventory.pods.add(pod(
                "frontend",
                "report-123-pod",
                Map.of("job", "report"),
                List.of(owner("batch/v1", "Job", "report-123", "job-uid", true))));
        inventory.customResourceUsages.add(usageCandidate("frontend", "batch-tls", "batch-api"));

        KubernetesMappedCertificateUsage mapped = mapper.mapUsages(inventory).get(secretKey("batch-tls"));

        assertThat(mapped.impact().getAffectedWorkloads()).containsExactly("frontend/CronJob/report");
        assertThat(mapped.usages()).singleElement().satisfies(usage ->
                assertThat(usage.getAffectedWorkloads()).singleElement().satisfies(workload -> {
                    assertThat(workload.getApiVersion()).isEqualTo("batch/v1");
                    assertThat(workload.getKind()).isEqualTo("CronJob");
                    assertThat(workload.getName()).isEqualTo("report");
                }));
    }

    @Test
    void mapUsages_standalonePodInitContainerSecretRef_isReported() {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        V1Container initContainer = new V1Container()
                .name("tls-bootstrap")
                .env(List.of(new V1EnvVar()
                        .name("TLS_CERT")
                        .valueFrom(new V1EnvVarSource()
                                .secretKeyRef(new V1SecretKeySelector().name("pod-tls").key("tls.crt")))));
        inventory.pods.add(new V1Pod()
                .metadata(new V1ObjectMeta().namespace("frontend").name("standalone"))
                .spec(new V1PodSpec()
                        .initContainers(List.of(initContainer))
                        .containers(List.of(new V1Container().name("app")))));

        KubernetesMappedCertificateUsage mapped = mapper.mapUsages(inventory).get(secretKey("pod-tls"));

        assertThat(mapped).isNotNull();
        assertThat(mapped.usages()).singleElement().satisfies(usage -> {
            assertThat(usage.getKind()).isEqualTo("Pod");
            assertThat(usage.getName()).isEqualTo("standalone");
            assertThat(usage.getFieldPath())
                    .isEqualTo("spec.initContainers[0].env[0].valueFrom.secretKeyRef.name");
            assertThat(usage.getAffectedWorkloads()).singleElement().satisfies(workload ->
                    assertThat(workload.getContainers()).containsExactly("app", "tls-bootstrap"));
        });
    }

    private KubernetesCertificateUsageCandidate usageCandidate(
            String namespace,
            String secretName,
            String serviceName) {
        return usageCandidate(namespace, secretName, namespace, serviceName, List.of("api.example.com"));
    }

    private KubernetesCertificateUsageCandidate usageCandidate(
            String certificateNamespace,
            String secretName,
            String serviceNamespace,
            String serviceName,
            List<String> hostnames) {
        KubernetesBackendServiceRef backend = KubernetesBackendServiceRef.builder()
                .namespace(serviceNamespace)
                .name(serviceName)
                .portNumber(443)
                .build();
        return new KubernetesCertificateUsageCandidate(
                "Secret",
                certificateNamespace,
                secretName,
                KubernetesCertificateUsage.builder()
                        .apiVersion("example.io/v1")
                        .kind("ExampleRoute")
                        .namespace(certificateNamespace)
                        .name("route")
                        .usageType("TLS_TERMINATION")
                        .hostnames(hostnames)
                        .backendServices(List.of(backend))
                        .affectedWorkloads(List.of())
                        .confidence("HIGH")
                        .build(),
                List.of(backend));
    }

    private KubernetesCertificateUsageCandidate usageCandidate(
            String namespace,
            String secretName,
            String serviceName,
            List<String> hostnames) {
        return usageCandidate(namespace, secretName, namespace, serviceName, hostnames);
    }

    private V1IngressRule ingressRule(String host, String serviceName) {
        return new V1IngressRule()
                .host(host)
                .http(new V1HTTPIngressRuleValue().paths(List.of(new V1HTTPIngressPath()
                        .backend(new V1IngressBackend().service(new V1IngressServiceBackend()
                                .name(serviceName)
                                .port(new V1ServiceBackendPort().number(443)))))));
    }

    private V1Service service(String namespace, String name, Map<String, String> selector) {
        return new V1Service()
                .metadata(new V1ObjectMeta().namespace(namespace).name(name))
                .spec(new V1ServiceSpec().selector(selector));
    }

    private V1Pod pod(
            String namespace,
            String name,
            Map<String, String> labels,
            List<V1OwnerReference> owners) {
        return new V1Pod()
                .metadata(new V1ObjectMeta()
                        .namespace(namespace)
                        .name(name)
                        .labels(labels)
                        .ownerReferences(owners))
                .spec(new V1PodSpec().containers(List.of(new V1Container().name("worker"))));
    }

    private V1OwnerReference owner(
            String apiVersion,
            String kind,
            String name,
            String uid,
            boolean controller) {
        return new V1OwnerReference()
                .apiVersion(apiVersion)
                .kind(kind)
                .name(name)
                .uid(uid)
                .controller(controller);
    }

    private String secretKey(String secretName) {
        return KubernetesParsedCertificate.usageLookupKey("Secret", "frontend", secretName);
    }
}
