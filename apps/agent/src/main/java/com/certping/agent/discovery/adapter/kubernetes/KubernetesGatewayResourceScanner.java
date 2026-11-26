// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesCertificateUsage;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.intAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.listAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.stringAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.stringsAt;

final class KubernetesGatewayResourceScanner {

    private static final String GROUP = "gateway.networking.k8s.io";
    private static final String VERSION = "v1";

    private final KubernetesDynamicResourceClient dynamicResourceClient;

    KubernetesGatewayResourceScanner(KubernetesDynamicResourceClient dynamicResourceClient) {
        this.dynamicResourceClient = dynamicResourceClient;
    }

    void scan(KubeApis.CustomObjects api, KubernetesClusterInventory inventory) {
        GatewayRouteIndex routeIndex = new GatewayRouteIndex();
        inventory.namespaces.forEach(namespace -> scanRoutes(api, namespace, inventory, routeIndex));
        inventory.namespaces.forEach(namespace -> scanGateways(api, namespace, inventory, routeIndex));
    }

    private void scanGateways(KubeApis.CustomObjects api,
            String namespace,
            KubernetesClusterInventory inventory,
            GatewayRouteIndex routeIndex) {
        dynamicResourceClient.scanNamespaced(api, inventory, namespace, GROUP, VERSION, "gateways",
                "Gateway", item -> {
                    String gatewayName = name(item);
                    List<Map<String, Object>> listeners = listAt(item, "spec", "listeners");
                    for (int listenerIndex = 0; listenerIndex < listeners.size(); listenerIndex++) {
                        addListenerUsages(inventory, namespace, gatewayName, item, listeners.get(listenerIndex),
                                listenerIndex, routeIndex);
                    }
                });
    }

    private void addListenerUsages(KubernetesClusterInventory inventory,
            String namespace,
            String gatewayName,
            Map<String, Object> gateway,
            Map<String, Object> listener,
            int listenerIndex,
            GatewayRouteIndex routeIndex) {
        String listenerName = stringAt(listener, "name");
        List<KubernetesBackendServiceRef> backends =
                routeIndex.backendServicesFor(namespace, gatewayName, listenerName);
        List<String> hostnames = mergeHostnames(
                stringAt(listener, "hostname"), routeIndex.hostnamesFor(namespace, gatewayName, listenerName));
        List<Map<String, Object>> refs = listAt(listener, "tls", "certificateRefs");
        for (int refIndex = 0; refIndex < refs.size(); refIndex++) {
            Map<String, Object> ref = refs.get(refIndex);
            String refName = stringAt(ref, "name");
            if (!isSecretReference(ref, refName)) {
                continue;
            }
            String certificateNamespace = stringAt(ref, "namespace");
            if (certificateNamespace == null || certificateNamespace.isBlank()) {
                certificateNamespace = namespace;
            }
            inventory.customResourceUsages.add(new KubernetesCertificateUsageCandidate(
                    "Secret",
                    certificateNamespace,
                    refName,
                    KubernetesCertificateUsage.builder()
                            .apiVersion(GROUP + "/" + VERSION)
                            .kind("Gateway")
                            .namespace(namespace)
                            .name(gatewayName)
                            .uid(uid(gateway))
                            .fieldPath("spec.listeners[" + listenerIndex + "].tls.certificateRefs["
                                    + refIndex + "].name")
                            .usageType("TLS_TERMINATION")
                            .hostnames(hostnames)
                            .backendServices(backends)
                            .affectedWorkloads(List.of())
                            .confidence("HIGH")
                            .build(),
                    backends));
        }
    }

    private boolean isSecretReference(Map<String, Object> ref, String refName) {
        if (refName == null || refName.isBlank()) {
            return false;
        }
        String kind = stringAt(ref, "kind");
        if (kind != null && !"Secret".equals(kind)) {
            return false;
        }
        String group = stringAt(ref, "group");
        return group == null || group.isBlank();
    }

    private void scanRoutes(KubeApis.CustomObjects api,
            String namespace,
            KubernetesClusterInventory inventory,
            GatewayRouteIndex index) {
        scanRouteKind(api, namespace, inventory, index, "httproutes", "HTTPRoute");
        scanRouteKind(api, namespace, inventory, index, "tlsroutes", "TLSRoute");
        scanRouteKind(api, namespace, inventory, index, "tcproutes", "TCPRoute");
    }

    private void scanRouteKind(KubeApis.CustomObjects api,
            String namespace,
            KubernetesClusterInventory inventory,
            GatewayRouteIndex index,
            String plural,
            String kind) {
        dynamicResourceClient.scanNamespaced(api, inventory, namespace, GROUP, VERSION, plural, kind,
                item -> {
                    List<String> hostnames = stringsAt(item, "spec", "hostnames");
                    List<KubernetesBackendServiceRef> backends = routeBackendServices(namespace, item);
                    for (Map<String, Object> parentRef : listAt(item, "spec", "parentRefs")) {
                        addParentBinding(namespace, index, parentRef, hostnames, backends);
                    }
                });
    }

    private void addParentBinding(String routeNamespace,
            GatewayRouteIndex index,
            Map<String, Object> parentRef,
            List<String> hostnames,
            List<KubernetesBackendServiceRef> backends) {
        String parentGroup = stringAt(parentRef, "group");
        if (parentGroup != null && !parentGroup.isBlank() && !GROUP.equals(parentGroup)) {
            return;
        }
        String parentKind = stringAt(parentRef, "kind");
        if (parentKind != null && !"Gateway".equals(parentKind)) {
            return;
        }
        String gatewayName = stringAt(parentRef, "name");
        if (gatewayName == null || gatewayName.isBlank()) {
            return;
        }
        String gatewayNamespace = stringAt(parentRef, "namespace");
        if (gatewayNamespace == null || gatewayNamespace.isBlank()) {
            gatewayNamespace = routeNamespace;
        }
        index.add(gatewayNamespace, gatewayName, stringAt(parentRef, "sectionName"), hostnames, backends);
    }

    private List<KubernetesBackendServiceRef> routeBackendServices(String namespace,
            Map<String, Object> route) {
        List<KubernetesBackendServiceRef> services = new ArrayList<>();
        for (Map<String, Object> rule : listAt(route, "spec", "rules")) {
            for (Map<String, Object> backendRef : listAt(rule, "backendRefs")) {
                String group = stringAt(backendRef, "group");
                String kind = stringAt(backendRef, "kind");
                String name = stringAt(backendRef, "name");
                if ((group != null && !group.isBlank())
                        || (kind != null && !"Service".equals(kind))
                        || name == null
                        || name.isBlank()) {
                    continue;
                }
                String serviceNamespace = stringAt(backendRef, "namespace");
                services.add(KubernetesBackendServiceRef.builder()
                        .namespace(serviceNamespace == null || serviceNamespace.isBlank()
                                ? namespace
                                : serviceNamespace)
                        .name(name)
                        .portNumber(intAt(backendRef, "port"))
                        .build());
            }
        }
        return services.stream()
                .distinct()
                .sorted(Comparator.comparing(this::backendSortKey))
                .toList();
    }

    private List<String> mergeHostnames(String listenerHostname, List<String> routeHostnames) {
        Set<String> hostnames = new LinkedHashSet<>();
        if (listenerHostname != null && !listenerHostname.isBlank()) {
            hostnames.add(listenerHostname);
        }
        hostnames.addAll(routeHostnames);
        return hostnames.stream().sorted().toList();
    }

    private String name(Map<String, Object> item) {
        return stringAt(item, "metadata", "name");
    }

    private String uid(Map<String, Object> item) {
        return stringAt(item, "metadata", "uid");
    }

    private String backendSortKey(KubernetesBackendServiceRef service) {
        return service.getNamespace() + "/" + service.getName() + "/" + service.getPortNumber();
    }

    private static final class GatewayRouteIndex {
        private final Map<String, List<GatewayRouteBinding>> bindingsByGateway = new LinkedHashMap<>();

        void add(String namespace,
                String name,
                String sectionName,
                List<String> hostnames,
                List<KubernetesBackendServiceRef> backendServices) {
            bindingsByGateway.computeIfAbsent(key(namespace, name), ignored -> new ArrayList<>())
                    .add(new GatewayRouteBinding(sectionName, hostnames, backendServices));
        }

        List<String> hostnamesFor(String namespace, String name, String listenerName) {
            return matchingBindings(namespace, name, listenerName).stream()
                    .flatMap(binding -> binding.hostnames().stream())
                    .distinct()
                    .sorted()
                    .toList();
        }

        List<KubernetesBackendServiceRef> backendServicesFor(String namespace,
                String name,
                String listenerName) {
            return matchingBindings(namespace, name, listenerName).stream()
                    .flatMap(binding -> binding.backendServices().stream())
                    .distinct()
                    .sorted(Comparator.comparing(service -> service.getNamespace() + "/" + service.getName()))
                    .toList();
        }

        private List<GatewayRouteBinding> matchingBindings(String namespace, String name, String listenerName) {
            return bindingsByGateway.getOrDefault(key(namespace, name), List.of()).stream()
                    .filter(binding -> binding.sectionName() == null
                            || binding.sectionName().isBlank()
                            || binding.sectionName().equals(listenerName))
                    .toList();
        }

        private static String key(String namespace, String name) {
            return namespace + "/" + name;
        }

        private record GatewayRouteBinding(
                String sectionName,
                List<String> hostnames,
                List<KubernetesBackendServiceRef> backendServices) {
        }
    }
}
