// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesCertificateUsage;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.intAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.listAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.mapAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.stringAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.stringsAt;

@Component
@RequiredArgsConstructor
class KubernetesCustomResourceScanner {

    private static final Pattern TRAEFIK_HOST_MATCHER =
            Pattern.compile("\\bHost(?:SNI)?\\s*\\(([^)]*)\\)");
    private static final Pattern TRAEFIK_QUOTED_HOST_MATCHER =
            Pattern.compile("[`'\"]([^`'\"]+)[`'\"]");

    private final KubernetesCertificateParser certificateParser;
    private final KubernetesDynamicResourceClient dynamicResourceClient = new KubernetesDynamicResourceClient();
    private final KubernetesGatewayResourceScanner gatewayResourceScanner =
            new KubernetesGatewayResourceScanner(dynamicResourceClient);

    void scan(KubeApis.ApiExtensions extensionsApi,
            KubeApis.CustomObjects customObjectsApi,
            KubernetesClusterInventory inventory,
            String clusterName) {
        dynamicResourceClient.loadCatalog(extensionsApi, inventory);
        gatewayResourceScanner.scan(customObjectsApi, inventory);
        scanTraefik(customObjectsApi, inventory);
        for (String namespace : inventory.namespaces) {
            scanIstio(customObjectsApi, namespace, inventory);
            scanContour(customObjectsApi, namespace, inventory);
            scanOpenShiftRoutes(customObjectsApi, namespace, inventory, clusterName);
        }
    }

    private void scanTraefik(KubeApis.CustomObjects api, KubernetesClusterInventory inventory) {
        KubernetesTraefikServiceIndex serviceIndex = new KubernetesTraefikServiceIndex();
        for (String namespace : inventory.namespaces) {
            scanNamespaced(api, inventory, namespace, "traefik.io", "v1alpha1", "traefikservices",
                    "TraefikService", serviceIndex::add);
            scanNamespaced(api, inventory, namespace, "traefik.containo.us", "v1alpha1", "traefikservices",
                    "TraefikService", serviceIndex::add);
        }
        for (String namespace : inventory.namespaces) {
            scanNamespaced(api, inventory, namespace, "traefik.io", "v1alpha1", "ingressroutes",
                    "IngressRoute", item -> addTraefikTls(namespace, inventory, item, "traefik.io/v1alpha1",
                            "IngressRoute", serviceIndex));
            scanNamespaced(api, inventory, namespace, "traefik.containo.us", "v1alpha1", "ingressroutes",
                    "IngressRoute", item -> addTraefikTls(namespace, inventory, item, "traefik.containo.us/v1alpha1",
                            "IngressRoute", serviceIndex));
            scanNamespaced(api, inventory, namespace, "traefik.io", "v1alpha1", "ingressroutetcps",
                    "IngressRouteTCP", item -> addTraefikTls(namespace, inventory, item, "traefik.io/v1alpha1",
                            "IngressRouteTCP", serviceIndex));
        }
    }

    private void addTraefikTls(String namespace,
            KubernetesClusterInventory inventory,
            Map<String, Object> item,
            String apiVersion,
            String kind,
            KubernetesTraefikServiceIndex serviceIndex) {
        String secretName = stringAt(item, "spec", "tls", "secretName");
        if (secretName == null || secretName.isBlank()) {
            return;
        }
        List<KubernetesBackendServiceRef> backendServices = traefikBackendServices(namespace, item, serviceIndex);
        List<String> hostnames = traefikHostnames(item);
        inventory.customResourceUsages.add(new KubernetesCertificateUsageCandidate(
                "Secret",
                namespace,
                secretName,
                KubernetesCertificateUsage.builder()
                        .apiVersion(apiVersion)
                        .kind(kind)
                        .namespace(namespace)
                        .name(name(item))
                        .uid(uid(item))
                        .fieldPath("spec.tls.secretName")
                        .usageType("TLS_TERMINATION")
                        .hostnames(hostnames)
                        .backendServices(backendServices)
                        .affectedWorkloads(List.of())
                        .confidence("HIGH")
                        .build(),
                backendServices));
    }

    private void scanIstio(KubeApis.CustomObjects api, String namespace, KubernetesClusterInventory inventory) {
        scanNamespaced(api, inventory, namespace, "networking.istio.io", "v1beta1", "gateways",
                "Gateway", item -> {
                    List<Map<String, Object>> servers = listAt(item, "spec", "servers");
                    for (int i = 0; i < servers.size(); i++) {
                        Map<String, Object> server = servers.get(i);
                        String secretName = stringAt(server, "tls", "credentialName");
                        if (secretName == null || secretName.isBlank()) {
                            continue;
                        }
                        inventory.customResourceUsages.add(new KubernetesCertificateUsageCandidate(
                                "Secret",
                                namespace,
                                secretName,
                                KubernetesCertificateUsage.builder()
                                        .apiVersion("networking.istio.io/v1beta1")
                                        .kind("Gateway")
                                        .namespace(namespace)
                                        .name(name(item))
                                        .uid(uid(item))
                                        .fieldPath("spec.servers[" + i + "].tls.credentialName")
                                        .usageType("TLS_TERMINATION")
                                        .hostnames(stringsAt(server, "hosts"))
                                        .backendServices(List.of())
                                        .affectedWorkloads(List.of())
                                        .confidence("MEDIUM")
                                        .build(),
                                List.of()));
                    }
                });
    }

    private void scanContour(KubeApis.CustomObjects api, String namespace, KubernetesClusterInventory inventory) {
        scanNamespaced(api, inventory, namespace, "projectcontour.io", "v1", "httpproxies",
                "HTTPProxy", item -> {
                    String secretName = stringAt(item, "spec", "virtualhost", "tls", "secretName");
                    if (secretName == null || secretName.isBlank()) {
                        return;
                    }
                    NamespacedName certificateSecret = namespacedName(namespace, secretName);
                    List<KubernetesBackendServiceRef> backendServices = contourBackendServices(namespace, item);
                    String fqdn = stringAt(item, "spec", "virtualhost", "fqdn");
                    inventory.customResourceUsages.add(new KubernetesCertificateUsageCandidate(
                            "Secret",
                            certificateSecret.namespace(),
                            certificateSecret.name(),
                            KubernetesCertificateUsage.builder()
                                    .apiVersion("projectcontour.io/v1")
                                    .kind("HTTPProxy")
                                    .namespace(namespace)
                                    .name(name(item))
                                    .uid(uid(item))
                                    .fieldPath("spec.virtualhost.tls.secretName")
                                    .usageType("TLS_TERMINATION")
                                    .hostnames(fqdn == null || fqdn.isBlank() ? List.of() : List.of(fqdn))
                                    .backendServices(backendServices)
                                    .affectedWorkloads(List.of())
                                    .confidence("HIGH")
                                    .build(),
                            backendServices));
                });
    }

    private void scanOpenShiftRoutes(KubeApis.CustomObjects api,
            String namespace,
            KubernetesClusterInventory inventory,
            String clusterName) {
        scanNamespaced(api, inventory, namespace, "route.openshift.io", "v1", "routes",
                "Route", false, item -> {
                    String host = stringAt(item, "spec", "host");
                    List<KubernetesBackendServiceRef> backendServices = openShiftBackendServices(namespace, item);
                    String inlineCertificate = stringAt(item, "spec", "tls", "certificate");
                    if (inlineCertificate != null && !inlineCertificate.isBlank()) {
                        KubernetesParsedCertificate parsed = certificateParser.parseInlineCustomResourceCertificate(
                                clusterName,
                                "route.openshift.io/v1",
                                "Route",
                                namespace,
                                name(item),
                                uid(item),
                                resourceVersion(item),
                                "spec.tls.certificate",
                                inlineCertificate);
                        if (parsed != null) {
                            inventory.inlineCertificates.add(parsed);
                            inventory.customResourceUsages.add(new KubernetesCertificateUsageCandidate(
                                    "Route",
                                    namespace,
                                    name(item),
                                    KubernetesCertificateUsage.builder()
                                            .apiVersion("route.openshift.io/v1")
                                            .kind("Route")
                                            .namespace(namespace)
                                            .name(name(item))
                                            .uid(uid(item))
                                            .fieldPath("spec.tls.certificate")
                                            .usageType("TLS_TERMINATION")
                                            .hostnames(host == null ? List.of() : List.of(host))
                                            .backendServices(backendServices)
                                            .affectedWorkloads(List.of())
                                            .confidence("HIGH")
                                            .build(),
                                    backendServices));
                        }
                    }
                    String secretName = stringAt(item, "spec", "tls", "externalCertificate", "name");
                    if (secretName == null || secretName.isBlank()) {
                        return;
                    }
                    inventory.customResourceUsages.add(new KubernetesCertificateUsageCandidate(
                            "Secret",
                            namespace,
                            secretName,
                            KubernetesCertificateUsage.builder()
                                    .apiVersion("route.openshift.io/v1")
                                    .kind("Route")
                                    .namespace(namespace)
                                    .name(name(item))
                                    .uid(uid(item))
                                    .fieldPath("spec.tls.externalCertificate.name")
                                    .usageType("TLS_TERMINATION")
                                    .hostnames(host == null ? List.of() : List.of(host))
                                    .backendServices(backendServices)
                                    .affectedWorkloads(List.of())
                                    .confidence("HIGH")
                                    .build(),
                            backendServices));
                });
    }

    private void scanNamespaced(KubeApis.CustomObjects api,
            KubernetesClusterInventory inventory,
            String namespace,
            String group,
            String version,
            String plural,
            String kind,
            KubernetesDynamicResourceClient.CustomObjectConsumer consumer) {
        dynamicResourceClient.scanNamespaced(
                api, inventory, namespace, group, version, plural, kind, consumer);
    }

    private void scanNamespaced(KubeApis.CustomObjects api,
            KubernetesClusterInventory inventory,
            String namespace,
            String group,
            String version,
            String plural,
            String kind,
            boolean useCustomResourceCatalog,
            KubernetesDynamicResourceClient.CustomObjectConsumer consumer) {
        dynamicResourceClient.scanNamespaced(
                api, inventory, namespace, group, version, plural, kind,
                useCustomResourceCatalog, consumer);
    }

    private List<KubernetesBackendServiceRef> traefikBackendServices(String namespace,
            Map<String, Object> route,
            KubernetesTraefikServiceIndex serviceIndex) {
        List<KubernetesBackendServiceRef> services = new ArrayList<>();
        for (Map<String, Object> routeEntry : listAt(route, "spec", "routes")) {
            for (Map<String, Object> service : listAt(routeEntry, "services")) {
                addTraefikBackendService(namespace, service, serviceIndex, services);
            }
        }
        return sortedBackendServices(services);
    }

    private void addTraefikBackendService(String defaultNamespace,
            Map<String, Object> service,
            KubernetesTraefikServiceIndex serviceIndex,
            List<KubernetesBackendServiceRef> services) {
        String kind = stringAt(service, "kind");
        if ("TraefikService".equals(kind)) {
            String namespace = stringAt(service, "namespace");
            services.addAll(serviceIndex.nativeServicesFor(
                    namespace == null || namespace.isBlank() ? defaultNamespace : namespace,
                    stringAt(service, "name")));
            return;
        }
        addNamedBackendService(defaultNamespace, service, services);
    }

    private List<String> traefikHostnames(Map<String, Object> ingressRoute) {
        Set<String> hostnames = new LinkedHashSet<>();
        for (Map<String, Object> route : listAt(ingressRoute, "spec", "routes")) {
            String match = stringAt(route, "match");
            if (match == null || match.isBlank()) {
                continue;
            }
            Matcher hostMatcher = TRAEFIK_HOST_MATCHER.matcher(match);
            while (hostMatcher.find()) {
                Matcher quotedHostMatcher = TRAEFIK_QUOTED_HOST_MATCHER.matcher(hostMatcher.group(1));
                while (quotedHostMatcher.find()) {
                    String hostname = quotedHostMatcher.group(1).trim();
                    if (!hostname.isBlank()) {
                        hostnames.add(hostname);
                    }
                }
            }
        }
        return hostnames.stream().sorted().toList();
    }

    private List<KubernetesBackendServiceRef> contourBackendServices(String namespace, Map<String, Object> proxy) {
        List<KubernetesBackendServiceRef> services = new ArrayList<>();
        for (Map<String, Object> route : listAt(proxy, "spec", "routes")) {
            for (Map<String, Object> service : listAt(route, "services")) {
                addNamedBackendService(namespace, service, services);
            }
        }
        for (Map<String, Object> service : listAt(proxy, "spec", "tcpproxy", "services")) {
            addNamedBackendService(namespace, service, services);
        }
        return sortedBackendServices(services);
    }

    private List<KubernetesBackendServiceRef> openShiftBackendServices(String namespace, Map<String, Object> route) {
        List<KubernetesBackendServiceRef> services = new ArrayList<>();
        Map<String, Object> primary = mapAt(route, "spec", "to");
        if (!primary.isEmpty()) {
            addNamedBackendService(namespace, primary, services);
        }
        for (Map<String, Object> alternate : listAt(route, "spec", "alternateBackends")) {
            addNamedBackendService(namespace, alternate, services);
        }
        return sortedBackendServices(services);
    }

    private void addNamedBackendService(String defaultNamespace,
            Map<String, Object> service,
            List<KubernetesBackendServiceRef> services) {
        String kind = stringAt(service, "kind");
        if (kind != null && !"Service".equals(kind)) {
            return;
        }
        String name = stringAt(service, "name");
        if (name == null || name.isBlank()) {
            return;
        }
        String namespace = stringAt(service, "namespace");
        services.add(KubernetesBackendServiceRef.builder()
                .namespace(namespace == null || namespace.isBlank() ? defaultNamespace : namespace)
                .name(name)
                .portName(stringAt(service, "port"))
                .portNumber(intAt(service, "port"))
                .build());
    }

    private List<KubernetesBackendServiceRef> sortedBackendServices(List<KubernetesBackendServiceRef> services) {
        return services.stream()
                .distinct()
                .sorted(java.util.Comparator.comparing(this::backendServiceSortKey))
                .toList();
    }

    private NamespacedName namespacedName(String defaultNamespace, String value) {
        int separator = value.indexOf('/');
        if (separator > 0 && separator == value.lastIndexOf('/') && separator < value.length() - 1) {
            return new NamespacedName(value.substring(0, separator), value.substring(separator + 1));
        }
        return new NamespacedName(defaultNamespace, value);
    }

    private String backendServiceSortKey(KubernetesBackendServiceRef service) {
        return service.getNamespace() + "/" + service.getName() + "/" + service.getPortNumber();
    }

    private String name(Map<String, Object> item) {
        return stringAt(item, "metadata", "name");
    }

    private String uid(Map<String, Object> item) {
        return stringAt(item, "metadata", "uid");
    }

    private String resourceVersion(Map<String, Object> item) {
        return stringAt(item, "metadata", "resourceVersion");
    }

    private record NamespacedName(String namespace, String name) {
    }

}
