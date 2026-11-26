// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinition;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionList;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionSpec;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionVersion;
import io.kubernetes.client.openapi.models.V1ListMeta;
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

class KubernetesCustomResourceScannerTest {

    private final KubernetesCertificateParser certificateParser = new KubernetesCertificateParser();
    private final KubernetesCustomResourceScanner scanner = new KubernetesCustomResourceScanner(certificateParser);
    private final KubernetesUsageMapper usageMapper = new KubernetesUsageMapper();

    @Test
    void scan_gatewayCertificateRef_resolvesHttpRouteBackendsToServicesAndWorkloads() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(invocation -> {
                    String plural = invocation.getArgument(3);
                    return switch (plural) {
                        case "httproutes" -> customObjectList(httpRoute());
                        case "gateways" -> customObjectList(gateway());
                        default -> customObjectList();
                    };
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("frontend");
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("gateways.gateway.networking.k8s.io");
        inventory.installedCustomResources.add("httproutes.gateway.networking.k8s.io");
        inventory.services.add(service("frontend", "api-service", Map.of("app", "api")));
        inventory.pods.add(pod("frontend", "api-pod", Map.of("app", "api"), "rs-1"));
        inventory.replicaSets.add(replicaSet("frontend", "api-rs", "rs-1", "api"));

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        Map<String, KubernetesMappedCertificateUsage> usages = usageMapper.mapUsages(inventory);
        KubernetesMappedCertificateUsage usage = usages.get(
                KubernetesParsedCertificate.usageLookupKey("Secret", "frontend", "api-tls"));

        assertThat(usage).isNotNull();
        assertThat(usage.usages()).hasSize(1);
        assertThat(usage.usages().get(0).getKind()).isEqualTo("Gateway");
        assertThat(usage.usages().get(0).getBackendServices())
                .extracting(service -> service.getNamespace() + "/" + service.getName())
                .containsExactly("frontend/api-service");
        assertThat(usage.impact().getAffectedServices()).containsExactly("frontend/api-service");
        assertThat(usage.impact().getAffectedWorkloads()).containsExactly("frontend/Deployment/api");
        assertThat(usage.impact().getAffectedHostnames()).containsExactly("api.example.com");
    }

    @Test
    void scan_customResourceListIsForbidden_marksUsageIncomplete() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(extensionsApi.listCustomResourceDefinitions(any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("frontend");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.usageComplete()).isFalse();
        assertThat(inventory.unreadableResourceTypes).contains("HTTPRoute", "Gateway");
        assertThat(inventory.warnings)
                .anyMatch(warning -> warning.contains("usage and impact are incomplete"));
    }

    @Test
    void scan_absentCataloguedCustomResource_doesNotMarkUsageIncomplete() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(extensionsApi.listCustomResourceDefinitions(any(), any()))
                .thenReturn(new V1CustomResourceDefinitionList()
                        .metadata(new V1ListMeta())
                        .items(List.of(crd("httproutes.gateway.networking.k8s.io"))));
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(customObjectList());

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("frontend");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.customResourceCatalogComplete).isTrue();
        assertThat(inventory.usageComplete()).isTrue();
        assertThat(inventory.unreadableResourceTypes).isEmpty();
    }

    @Test
    void scan_legacyTraefikInstalledButForbidden_marksUsageIncomplete() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(extensionsApi.listCustomResourceDefinitions(any(), any()))
                .thenReturn(new V1CustomResourceDefinitionList()
                        .metadata(new V1ListMeta())
                        .items(List.of(
                                crd("ingressroutes.traefik.io"),
                                crd("ingressroutes.traefik.containo.us"))));
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(invocation -> {
                    String group = invocation.getArgument(0);
                    if ("traefik.containo.us".equals(group)) {
                        throw new ApiException(403, "forbidden");
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("frontend");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.usageComplete()).isFalse();
        assertThat(inventory.unreadableResourceTypes).containsExactly("IngressRoute");
        assertThat(inventory.warnings)
                .contains("Permission denied listing IngressRoute custom resources (grant list on "
                        + "ingressroutes.traefik.containo.us); usage and impact are incomplete");
    }

    @Test
    void scan_installedCustomResourceWithoutSupportedVersion_marksUsageIncomplete() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(extensionsApi.listCustomResourceDefinitions(any(), any()))
                .thenReturn(new V1CustomResourceDefinitionList()
                        .metadata(new V1ListMeta())
                        .items(List.of(crd("gateways.gateway.networking.k8s.io", "v1beta1"))));

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("frontend");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.usageComplete()).isFalse();
        assertThat(inventory.unreadableResourceTypes).containsExactly("Gateway");
        assertThat(inventory.warnings)
                .contains("Installed Gateway custom resource does not serve supported API version "
                        + "gateway.networking.k8s.io/v1; usage and impact are incomplete");
    }

    // ── scanIstio: Gateway with credentialName ─────────────────────────────

    @Test
    void scan_istioGatewayCredentialName_recordsUsage() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String group = inv.getArgument(0);
                    String plural = inv.getArgument(3);
                    if ("networking.istio.io".equals(group) && "gateways".equals(plural)) {
                        return customObjectList(istioGateway());
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("mesh");
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("gateways.networking.istio.io");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.customResourceUsages).anyMatch(u ->
                "istio-tls".equals(u.certificateName()) && "Secret".equals(u.certificateSourceKind()));
    }

    @Test
    void scan_istioGatewayWithoutTls_notRecorded() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String group = inv.getArgument(0);
                    String plural = inv.getArgument(3);
                    if ("networking.istio.io".equals(group) && "gateways".equals(plural)) {
                        return customObjectList(Map.of(
                                "metadata", Map.of("name", "no-tls-gw", "namespace", "mesh"),
                                "spec", Map.of("servers", List.of(Map.of(
                                        "hosts", List.of("no-tls.example.com"))))));
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("mesh");
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("gateways.networking.istio.io");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        // No TLS credential → no usage recorded.
        assertThat(inventory.customResourceUsages).noneMatch(u ->
                "Gateway".equals(u.usage().getKind()));
    }

    // ── scanContour: HTTPProxy with secretName ─────────────────────────────

    @Test
    void scan_contourHttpProxyWithTls_recordsUsage() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String group = inv.getArgument(0);
                    if ("projectcontour.io".equals(group)) {
                        return customObjectList(contourProxy());
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("web");
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("httpproxies.projectcontour.io");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.customResourceUsages).anyMatch(u ->
                "contour-tls".equals(u.certificateName())
                        && "HTTPProxy".equals(u.usage().getKind()));
    }

    @Test
    void scan_contourHttpProxyWithoutTls_notRecorded() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String group = inv.getArgument(0);
                    if ("projectcontour.io".equals(group)) {
                        return customObjectList(Map.of(
                                "metadata", Map.of("name", "plain", "namespace", "web"),
                                "spec", Map.of("virtualhost", Map.of("fqdn", "plain.example.com"))));
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("web");
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("httpproxies.projectcontour.io");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.customResourceUsages).noneMatch(u ->
                "HTTPProxy".equals(u.usage().getKind()));
    }

    // ── scanTraefik: IngressRoute with tls.secretName ──────────────────────

    @Test
    void scan_traefikIngressRouteWithTls_recordsUsage() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String group = inv.getArgument(0);
                    String plural = inv.getArgument(3);
                    if ("traefik.io".equals(group) && "ingressroutes".equals(plural)) {
                        return customObjectList(traefikIngressRoute());
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("frontend");
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("ingressroutes.traefik.io");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.customResourceUsages).anyMatch(u ->
                "traefik-tls".equals(u.certificateName())
                        && "IngressRoute".equals(u.usage().getKind()));
    }

    // ── scanOpenShiftRoutes: inline certificate on Route ───────────────────

    @Test
    void scan_openShiftRouteWithoutTls_notRecorded() throws Exception {
        KubeApis.ApiExtensions extensionsApi = mock(KubeApis.ApiExtensions.class);
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String group = inv.getArgument(0);
                    if ("route.openshift.io".equals(group)) {
                        return customObjectList(Map.of(
                                "metadata", Map.of("name", "plain-route", "namespace", "web"),
                                "spec", Map.of("host", "plain-route.example.com")));
                    }
                    return customObjectList();
                });

        KubernetesClusterInventory inventory = new KubernetesClusterInventory();
        inventory.namespaces.add("web");

        scanner.scan(extensionsApi, api, inventory, "prod-aks");

        assertThat(inventory.inlineCertificates).isEmpty();
    }

    // ── fixture helpers for the CRD payload shapes above ───────────────────

    private Map<String, Object> istioGateway() {
        return Map.of(
                "metadata", Map.of("name", "edge-gw", "namespace", "mesh", "uid", "gw-1"),
                "spec", Map.of(
                        "servers", List.of(Map.of(
                                "hosts", List.of("api.example.com"),
                                "tls", Map.of("credentialName", "istio-tls")))));
    }

    private Map<String, Object> contourProxy() {
        return Map.of(
                "metadata", Map.of("name", "web-proxy", "namespace", "web", "uid", "hp-1"),
                "spec", Map.of(
                        "virtualhost", Map.of(
                                "fqdn", "web.example.com",
                                "tls", Map.of("secretName", "contour-tls"))));
    }

    private Map<String, Object> traefikIngressRoute() {
        return Map.of(
                "metadata", Map.of("name", "web-route", "namespace", "frontend", "uid", "ir-1"),
                "spec", Map.of(
                        "tls", Map.of("secretName", "traefik-tls"),
                        "routes", List.of(Map.of("match", "Host(`web.example.com`)"))));
    }

    private Map<String, Object> customObjectList(Map<String, Object>... items) {
        return Map.of(
                "metadata", Map.of(),
                "items", List.of(items));
    }

    private V1CustomResourceDefinition crd(String name) {
        return new V1CustomResourceDefinition()
                .metadata(new V1ObjectMeta().name(name));
    }

    private V1CustomResourceDefinition crd(String name, String servedVersion) {
        return crd(name)
                .spec(new V1CustomResourceDefinitionSpec()
                        .group(name.substring(name.indexOf('.') + 1))
                        .names(new io.kubernetes.client.openapi.models.V1CustomResourceDefinitionNames()
                                .kind("Test")
                                .plural(name.substring(0, name.indexOf('.'))))
                        .scope("Namespaced")
                        .versions(List.of(new V1CustomResourceDefinitionVersion()
                                .name(servedVersion)
                                .served(true)
                                .storage(true))));
    }

    private Map<String, Object> gateway() {
        return Map.of(
                "metadata", Map.of("name", "edge-gw", "namespace", "frontend", "uid", "gw-1"),
                "spec", Map.of(
                        "listeners", List.of(Map.of(
                                "hostname", "api.example.com",
                                "tls", Map.of(
                                        "certificateRefs", List.of(Map.of(
                                                "kind", "Secret",
                                                "name", "api-tls")))))));
    }

    private Map<String, Object> httpRoute() {
        return Map.of(
                "metadata", Map.of("name", "api-route", "namespace", "frontend", "uid", "route-1"),
                "spec", Map.of(
                        "hostnames", List.of("api.example.com"),
                        "parentRefs", List.of(Map.of(
                                "kind", "Gateway",
                                "name", "edge-gw")),
                        "rules", List.of(Map.of(
                                "backendRefs", List.of(Map.of(
                                        "kind", "Service",
                                        "name", "api-service",
                                        "port", 443))))));
    }

    private V1Service service(String namespace, String name, Map<String, String> selector) {
        return new V1Service()
                .metadata(new V1ObjectMeta().namespace(namespace).name(name))
                .spec(new V1ServiceSpec().selector(selector));
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
                                .name("api-rs")
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
}
