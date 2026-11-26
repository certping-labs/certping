// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KubernetesCustomResourceImpactTest {

    private final KubernetesCustomResourceScanner scanner =
            new KubernetesCustomResourceScanner(new KubernetesCertificateParser());
    private final KubernetesUsageMapper usageMapper = new KubernetesUsageMapper();

    @Test
    void scan_crossNamespaceHttpRoute_mapsOnlyItsTargetGatewayListener() throws Exception {
        KubeApis.CustomObjects api = customObjectsApi((group, namespace, plural) -> {
            if ("httproutes".equals(plural) && "frontend".equals(namespace)) {
                return list(httpRoute());
            }
            if ("gateways".equals(plural) && "gateway-system".equals(namespace)) {
                return list(gateway());
            }
            return list();
        });
        KubernetesClusterInventory inventory = cataloguedInventory(
                "gateways.gateway.networking.k8s.io",
                "httproutes.gateway.networking.k8s.io");
        inventory.namespaces.addAll(List.of("frontend", "gateway-system"));
        inventory.services.add(service("frontend", "api-service"));

        scanner.scan(mock(KubeApis.ApiExtensions.class), api, inventory, "prod");

        Map<String, KubernetesMappedCertificateUsage> usages = usageMapper.mapUsages(inventory);
        KubernetesMappedCertificateUsage edge = usages.get(secretKey("gateway-system", "edge-tls"));
        KubernetesMappedCertificateUsage admin = usages.get(secretKey("gateway-system", "admin-tls"));
        assertThat(edge.impact().getAffectedHostnames())
                .containsExactly("api.example.com", "edge.example.com");
        assertThat(edge.impact().getAffectedServices()).containsExactly("frontend/api-service");
        assertThat(admin.impact().getAffectedHostnames()).containsExactly("admin.example.com");
        assertThat(admin.impact().getAffectedServices()).isEmpty();
    }

    @Test
    void scan_contourProxy_mapsDelegatedCertificateHostnameAndBackend() throws Exception {
        KubeApis.CustomObjects api = customObjectsApi((group, namespace, plural) ->
                "httpproxies".equals(plural) ? list(contourProxy()) : list());
        KubernetesClusterInventory inventory = cataloguedInventory("httpproxies.projectcontour.io");
        inventory.namespaces.add("frontend");
        inventory.services.add(service("frontend", "api-service"));

        scanner.scan(mock(KubeApis.ApiExtensions.class), api, inventory, "prod");

        KubernetesMappedCertificateUsage mapped = usageMapper.mapUsages(inventory)
                .get(secretKey("certificates", "shared-tls"));
        assertThat(mapped).isNotNull();
        assertThat(mapped.impact().getAffectedHostnames()).containsExactly("contour.example.com");
        assertThat(mapped.impact().getAffectedServices()).containsExactly("frontend/api-service");
    }

    @Test
    void scan_traefikIngressRoute_extractsHostnamesFromMatchRule() throws Exception {
        KubeApis.CustomObjects api = customObjectsApi((group, namespace, plural) -> {
            if ("ingressroutes".equals(plural)) {
                return list(traefikIngressRoute());
            }
            if ("traefikservices".equals(plural) && "shop".equals(namespace)) {
                return list(traefikService(), nestedTraefikService());
            }
            return list();
        });
        KubernetesClusterInventory inventory = cataloguedInventory(
                "ingressroutes.traefik.io",
                "traefikservices.traefik.io");
        inventory.namespaces.add("shop");
        inventory.services.add(service("shop", "web-app-stable"));
        inventory.services.add(service("shop", "web-app-canary"));
        inventory.pods.add(pod("shop", "app-pod", Map.of("app", "web-app-stable"), "rs-1"));
        inventory.replicaSets.add(replicaSet("shop", "app-rs", "rs-1", "web-app"));

        scanner.scan(mock(KubeApis.ApiExtensions.class), api, inventory, "prod");

        KubernetesMappedCertificateUsage mapped = usageMapper.mapUsages(inventory)
                .get(secretKey("shop", "web-tls"));

        assertThat(mapped).isNotNull();
        assertThat(mapped.usages()).hasSize(1);
        assertThat(mapped.usages().get(0).getHostnames()).containsExactly("app.example.com");
        assertThat(mapped.usages().get(0).getBackendServices())
                .extracting(service -> service.getNamespace() + "/" + service.getName())
                .containsExactly("shop/web-app-canary", "shop/web-app-stable");
        assertThat(mapped.impact().getAffectedHostnames()).containsExactly("app.example.com");
        assertThat(mapped.impact().getAffectedServices())
                .containsExactly("shop/web-app-canary", "shop/web-app-stable");
        assertThat(mapped.impact().getAffectedWorkloads()).containsExactly("shop/Deployment/web-app");
    }

    @Test
    void scan_traefikIngressRoute_resolvesCrossNamespaceTraefikServiceWithinScope() throws Exception {
        KubeApis.CustomObjects api = customObjectsApi((group, namespace, plural) -> {
            if ("ingressroutes".equals(plural) && "shop".equals(namespace)) {
                return list(crossNamespaceTraefikIngressRoute());
            }
            if ("traefikservices".equals(plural) && "platform-edge".equals(namespace)) {
                return list(crossNamespaceTraefikService());
            }
            return list();
        });
        KubernetesClusterInventory inventory = cataloguedInventory(
                "ingressroutes.traefik.io",
                "traefikservices.traefik.io");
        inventory.namespaces.addAll(List.of("platform-edge", "shop"));
        inventory.services.add(service("shop", "web-app-stable"));

        scanner.scan(mock(KubeApis.ApiExtensions.class), api, inventory, "prod");

        KubernetesMappedCertificateUsage mapped = usageMapper.mapUsages(inventory)
                .get(secretKey("shop", "web-tls"));

        assertThat(mapped).isNotNull();
        assertThat(mapped.impact().getAffectedHostnames()).containsExactly("app.example.com");
        assertThat(mapped.impact().getAffectedServices()).containsExactly("shop/web-app-stable");
    }

    @Test
    void scan_openShiftRouteWithoutCrdCatalogEntry_isStillProbedAndMapped() throws Exception {
        KubeApis.CustomObjects api = customObjectsApi((group, namespace, plural) ->
                "route.openshift.io".equals(group) ? list(openShiftRoute()) : list());
        KubernetesClusterInventory inventory = cataloguedInventory();
        inventory.namespaces.add("frontend");
        inventory.services.add(service("frontend", "api-service"));

        scanner.scan(mock(KubeApis.ApiExtensions.class), api, inventory, "prod");

        KubernetesMappedCertificateUsage mapped = usageMapper.mapUsages(inventory)
                .get(secretKey("frontend", "route-tls"));
        assertThat(mapped).isNotNull();
        assertThat(mapped.impact().getAffectedHostnames()).containsExactly("route.example.com");
        assertThat(mapped.impact().getAffectedServices()).containsExactly("frontend/api-service");
    }

    private KubernetesClusterInventory cataloguedInventory(String... resourceNames) {
        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.customResourceCatalogComplete = true;
        for (String resourceName : resourceNames) {
            inventory.installedCustomResources.add(resourceName);
        }
        return inventory;
    }

    private KubeApis.CustomObjects customObjectsApi(CustomObjectResponse response) throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(invocation -> response.get(
                        invocation.getArgument(0),
                        invocation.getArgument(2),
                        invocation.getArgument(3)));
        return api;
    }

    private Map<String, Object> gateway() {
        return Map.of(
                "metadata", Map.of("name", "shared-gateway", "namespace", "gateway-system"),
                "spec", Map.of("listeners", List.of(
                        Map.of(
                                "name", "https",
                                "hostname", "edge.example.com",
                                "tls", Map.of("certificateRefs", List.of(Map.of(
                                        "group", "",
                                        "kind", "Secret",
                                        "name", "edge-tls")))),
                        Map.of(
                                "name", "admin",
                                "hostname", "admin.example.com",
                                "tls", Map.of("certificateRefs", List.of(Map.of(
                                        "name", "admin-tls")))))));
    }

    private Map<String, Object> httpRoute() {
        return Map.of(
                "metadata", Map.of("name", "api-route", "namespace", "frontend"),
                "spec", Map.of(
                        "hostnames", List.of("api.example.com"),
                        "parentRefs", List.of(Map.of(
                                "group", "gateway.networking.k8s.io",
                                "kind", "Gateway",
                                "namespace", "gateway-system",
                                "name", "shared-gateway",
                                "sectionName", "https")),
                        "rules", List.of(Map.of("backendRefs", List.of(Map.of(
                                "group", "",
                                "kind", "Service",
                                "name", "api-service",
                                "port", 443))))));
    }

    private Map<String, Object> contourProxy() {
        return Map.of(
                "metadata", Map.of("name", "api", "namespace", "frontend"),
                "spec", Map.of(
                        "virtualhost", Map.of(
                                "fqdn", "contour.example.com",
                                "tls", Map.of("secretName", "certificates/shared-tls")),
                        "routes", List.of(Map.of("services", List.of(Map.of(
                                "name", "api-service",
                                "port", 443))))));
    }

    private Map<String, Object> traefikIngressRoute() {
        return Map.of(
                "metadata", Map.of("name", "web-app", "namespace", "shop"),
                "spec", Map.of(
                        "routes", List.of(Map.of(
                                "kind", "Rule",
                                "match", "Host(`app.example.com`) && PathPrefix(`/`)",
                                "services", List.of(Map.of(
                                        "kind", "TraefikService",
                                        "name", "web-app-traefik",
                                        "port", 80)))),
                        "tls", Map.of("secretName", "web-tls")));
    }

    private Map<String, Object> traefikService() {
        return Map.of(
                "metadata", Map.of("name", "web-app-traefik", "namespace", "shop"),
                "spec", Map.of(
                        "weighted", Map.of(
                                "services", List.of(
                                        Map.of("kind", "TraefikService",
                                                "name", "web-app-nested",
                                                "weight", 100),
                                        Map.of("kind", "Service",
                                                "name", "web-app-canary",
                                                "port", 80,
                                                "weight", 0)))));
    }

    private Map<String, Object> nestedTraefikService() {
        return Map.of(
                "metadata", Map.of("name", "web-app-nested", "namespace", "shop"),
                "spec", Map.of(
                        "mirroring", Map.of(
                                "kind", "Service",
                                "name", "web-app-stable",
                                "port", 80)));
    }

    private Map<String, Object> crossNamespaceTraefikIngressRoute() {
        return Map.of(
                "metadata", Map.of("name", "web-app", "namespace", "shop"),
                "spec", Map.of(
                        "routes", List.of(Map.of(
                                "kind", "Rule",
                                "match", "Host(`app.example.com`)",
                                "services", List.of(Map.of(
                                        "kind", "TraefikService",
                                        "namespace", "platform-edge",
                                        "name", "shared-edge-service")))),
                        "tls", Map.of("secretName", "web-tls")));
    }

    private Map<String, Object> crossNamespaceTraefikService() {
        return Map.of(
                "metadata", Map.of("name", "shared-edge-service", "namespace", "platform-edge"),
                "spec", Map.of(
                        "weighted", Map.of(
                                "services", List.of(Map.of(
                                        "kind", "Service",
                                        "namespace", "shop",
                                        "name", "web-app-stable",
                                        "port", 80)))));
    }

    private Map<String, Object> openShiftRoute() {
        return Map.of(
                "metadata", Map.of("name", "api", "namespace", "frontend"),
                "spec", Map.of(
                        "host", "route.example.com",
                        "to", Map.of("kind", "Service", "name", "api-service"),
                        "tls", Map.of("externalCertificate", Map.of("name", "route-tls"))));
    }

    @SafeVarargs
    private Map<String, Object> list(Map<String, Object>... items) {
        return Map.of("metadata", Map.of(), "items", List.of(items));
    }

    private V1Service service(String namespace, String name) {
        return new V1Service()
                .metadata(new V1ObjectMeta().namespace(namespace).name(name))
                .spec(new V1ServiceSpec().selector(Map.of("app", name)));
    }

    private V1Pod pod(String namespace, String name, Map<String, String> labels, String replicaSetUid) {
        return new V1Pod()
                .metadata(new V1ObjectMeta()
                        .namespace(namespace)
                        .name(name)
                        .labels(labels)
                        .ownerReferences(List.of(new V1OwnerReference()
                                .apiVersion("apps/v1")
                                .kind("ReplicaSet")
                                .name("app-rs")
                                .uid(replicaSetUid))))
                .spec(new V1PodSpec());
    }

    private V1ReplicaSet replicaSet(String namespace, String name, String uid, String deploymentName) {
        return new V1ReplicaSet()
                .metadata(new V1ObjectMeta()
                        .namespace(namespace)
                        .name(name)
                        .uid(uid)
                        .ownerReferences(List.of(new V1OwnerReference()
                                .apiVersion("apps/v1")
                                .kind("Deployment")
                                .name(deploymentName))));
    }

    private String secretKey(String namespace, String name) {
        return KubernetesParsedCertificate.usageLookupKey("Secret", namespace, name);
    }

    @FunctionalInterface
    private interface CustomObjectResponse {
        Object get(String group, String namespace, String plural);
    }
}
