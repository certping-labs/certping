// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesBackendServiceRef;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.intAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.listAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.mapAt;
import static com.certping.agent.discovery.adapter.kubernetes.KubernetesCustomObjectReader.stringAt;

final class KubernetesTraefikServiceIndex {

    private static final int MAX_RESOLUTION_DEPTH = 10;

    private final Map<String, Map<String, Object>> servicesByName = new LinkedHashMap<>();

    void add(Map<String, Object> item) {
        String namespace = stringAt(item, "metadata", "namespace");
        String name = stringAt(item, "metadata", "name");
        if (namespace == null || namespace.isBlank() || name == null || name.isBlank()) {
            return;
        }
        servicesByName.put(key(namespace, name), item);
    }

    List<KubernetesBackendServiceRef> nativeServicesFor(String namespace, String name) {
        if (namespace == null || namespace.isBlank() || name == null || name.isBlank()) {
            return List.of();
        }
        return sortedServices(resolve(namespace, name, new LinkedHashSet<>(), 0));
    }

    private List<KubernetesBackendServiceRef> resolve(String namespace,
            String name,
            Set<String> resolving,
            int depth) {
        if (depth > MAX_RESOLUTION_DEPTH) {
            return List.of();
        }
        String serviceKey = key(namespace, name);
        if (!resolving.add(serviceKey)) {
            return List.of();
        }
        Map<String, Object> item = servicesByName.get(serviceKey);
        if (item == null) {
            resolving.remove(serviceKey);
            return List.of();
        }
        List<KubernetesBackendServiceRef> services = new ArrayList<>();
        addWeightedServices(namespace, item, services, resolving, depth);
        addHrwServices(namespace, item, services, resolving, depth);
        addMirroringServices(namespace, item, services, resolving, depth);
        addFailoverServices(namespace, item, services, resolving, depth);
        resolving.remove(serviceKey);
        return services;
    }

    private void addWeightedServices(String namespace,
            Map<String, Object> item,
            List<KubernetesBackendServiceRef> services,
            Set<String> resolving,
            int depth) {
        for (Map<String, Object> service : listAt(item, "spec", "weighted", "services")) {
            addServiceReference(namespace, service, services, resolving, depth);
        }
    }

    private void addHrwServices(String namespace,
            Map<String, Object> item,
            List<KubernetesBackendServiceRef> services,
            Set<String> resolving,
            int depth) {
        for (Map<String, Object> service : listAt(item, "spec", "hrw", "services")) {
            addServiceReference(namespace, service, services, resolving, depth);
        }
    }

    private void addMirroringServices(String namespace,
            Map<String, Object> item,
            List<KubernetesBackendServiceRef> services,
            Set<String> resolving,
            int depth) {
        Map<String, Object> mirroring = mapAt(item, "spec", "mirroring");
        if (!mirroring.isEmpty()) {
            addServiceReference(namespace, mirroring, services, resolving, depth);
        }
        for (Map<String, Object> mirror : listAt(mirroring, "mirrors")) {
            addServiceReference(namespace, mirror, services, resolving, depth);
        }
    }

    private void addFailoverServices(String namespace,
            Map<String, Object> item,
            List<KubernetesBackendServiceRef> services,
            Set<String> resolving,
            int depth) {
        Map<String, Object> service = mapAt(item, "spec", "failover", "service");
        if (!service.isEmpty()) {
            addServiceReference(namespace, service, services, resolving, depth);
        }
        Map<String, Object> fallback = mapAt(item, "spec", "failover", "fallback");
        if (!fallback.isEmpty()) {
            addServiceReference(namespace, fallback, services, resolving, depth);
        }
    }

    private void addServiceReference(String defaultNamespace,
            Map<String, Object> service,
            List<KubernetesBackendServiceRef> services,
            Set<String> resolving,
            int depth) {
        String kind = stringAt(service, "kind");
        String name = stringAt(service, "name");
        if (name == null || name.isBlank()) {
            return;
        }
        String namespace = stringAt(service, "namespace");
        String resolvedNamespace = namespace == null || namespace.isBlank() ? defaultNamespace : namespace;
        if ("TraefikService".equals(kind)) {
            services.addAll(resolve(resolvedNamespace, name, resolving, depth + 1));
            return;
        }
        if (kind != null && !"Service".equals(kind)) {
            return;
        }
        services.add(KubernetesBackendServiceRef.builder()
                .namespace(resolvedNamespace)
                .name(name)
                .portName(stringAt(service, "port"))
                .portNumber(intAt(service, "port"))
                .build());
    }

    private List<KubernetesBackendServiceRef> sortedServices(List<KubernetesBackendServiceRef> services) {
        return services.stream()
                .distinct()
                .sorted(java.util.Comparator.comparing(this::sortKey))
                .toList();
    }

    private String sortKey(KubernetesBackendServiceRef service) {
        return service.getNamespace() + "/" + service.getName() + "/" + service.getPortNumber();
    }

    private String key(String namespace, String name) {
        return namespace + "/" + name;
    }
}
