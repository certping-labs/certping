// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1APIResourceList;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinition;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionList;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionVersion;
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
final class KubernetesDynamicResourceClient {

    void loadCatalog(KubeApis.ApiExtensions api, KubernetesClusterInventory inventory) {
        if (inventory.customResourceCatalogComplete) {
            return;
        }
        try {
            String next = null;
            do {
                V1CustomResourceDefinitionList result = api.listCustomResourceDefinitions(next, 500);
                if (result == null || result.getItems() == null) {
                    log.debug("Kubernetes CRD catalog response had no items; using direct resource probing");
                    return;
                }
                result.getItems().forEach(item -> addCatalogEntry(item, inventory));
                next = result.getMetadata() != null ? result.getMetadata().getContinue() : null;
            } while (next != null && !next.isBlank());
            inventory.customResourceCatalogComplete = true;
            log.info("Loaded Kubernetes CRD catalog resourceCount={}",
                    inventory.installedCustomResources.size());
        } catch (ApiException e) {
            // Reading CRD metadata is optional; individual API probes remain authoritative.
            log.info("Kubernetes CRD catalog unavailable; using direct resource probing statusCode={} requiredRbac=\"list customresourcedefinitions at cluster scope\"",
                    e.getCode());
        }
    }

    void scanNamespaced(KubeApis.CustomObjects api,
            KubernetesClusterInventory inventory,
            String namespace,
            String group,
            String version,
            String plural,
            String kind,
            CustomObjectConsumer consumer) {
        scanNamespaced(api, inventory, namespace, group, version, plural, kind, true, consumer);
    }

    void scanNamespaced(KubeApis.CustomObjects api,
            KubernetesClusterInventory inventory,
            String namespace,
            String group,
            String version,
            String plural,
            String kind,
            boolean useCatalog,
            CustomObjectConsumer consumer) {
        String resourceName = plural + "." + group;
        if (useCatalog && inventory.customResourceCatalogComplete) {
            if (!inventory.installedCustomResources.contains(resourceName)) {
                return;
            }
            Set<String> servedVersions = inventory.servedCustomResourceVersions.get(resourceName);
            if (servedVersions != null && !servedVersions.isEmpty() && !servedVersions.contains(version)) {
                markUnsupportedVersion(inventory, kind, group, version, resourceName, servedVersions);
                return;
            }
        }
        try {
            String next = null;
            do {
                Object result = api.listNamespaced(group, version, namespace, plural, next, 500);
                KubernetesCustomObjectReader.items(result).forEach(consumer::accept);
                next = KubernetesCustomObjectReader.continueToken(result);
            } while (next != null && !next.isBlank());
        } catch (ApiException e) {
            if (KubernetesDiscoveryErrorTranslator.isNotFound(e)) {
                return;
            }
            boolean forbidden = KubernetesDiscoveryErrorTranslator.isForbidden(e);
            // RBAC is checked before routing, so a resource type that is not installed also answers 403
            // when the identity lacks a rule for it. API discovery is open to every authenticated identity.
            if (forbidden && !servedByApiDiscovery(api, inventory, group, version, plural)) {
                log.debug("Kubernetes custom resource not installed resource={}.{} version={}", plural, group, version);
                return;
            }
            log.warn("Kubernetes custom resource usage inventory is incomplete kind={} group={} version={} plural={} namespace={} statusCode={} requiredRbac=\"list {}.{} resources in namespace {}\"",
                    kind, group, version, plural, namespace, e.getCode(), plural, group, namespace);
            inventory.unreadableResourceTypes.add(kind);
            inventory.warnings.add(forbidden
                    ? "Permission denied listing " + kind + " custom resources (grant list on " + plural + "."
                            + group + "); usage and impact are incomplete"
                    : "Unable to list " + kind
                            + " custom resources for Kubernetes discovery; usage and impact are incomplete");
        }
    }

    private boolean servedByApiDiscovery(KubeApis.CustomObjects api,
            KubernetesClusterInventory inventory,
            String group,
            String version,
            String plural) {
        return inventory.servedByApiDiscovery.computeIfAbsent(plural + "." + group + "/" + version, key -> {
            try {
                V1APIResourceList resources = api.listApiResources(group, version);
                if (resources == null || resources.getResources() == null) {
                    return true;
                }
                return resources.getResources().stream().anyMatch(r -> plural.equals(r.getName()));
            } catch (ApiException e) {
                return !KubernetesDiscoveryErrorTranslator.isNotFound(e);
            }
        });
    }

    private void addCatalogEntry(V1CustomResourceDefinition item, KubernetesClusterInventory inventory) {
        String name = item.getMetadata() != null ? item.getMetadata().getName() : null;
        if (name == null || name.isBlank()) {
            return;
        }
        inventory.installedCustomResources.add(name);
        Set<String> servedVersions = new LinkedHashSet<>();
        if (item.getSpec() != null && item.getSpec().getVersions() != null) {
            for (V1CustomResourceDefinitionVersion version : item.getSpec().getVersions()) {
                if (Boolean.TRUE.equals(version.getServed())
                        && version.getName() != null
                        && !version.getName().isBlank()) {
                    servedVersions.add(version.getName());
                }
            }
        }
        inventory.servedCustomResourceVersions.put(name, servedVersions);
    }

    private void markUnsupportedVersion(KubernetesClusterInventory inventory,
            String kind,
            String group,
            String version,
            String resourceName,
            Set<String> servedVersions) {
        log.warn("Kubernetes custom resource version unsupported resource={} supportedVersion={} servedVersions={}",
                resourceName, version, servedVersions);
        inventory.unreadableResourceTypes.add(kind);
        inventory.warnings.add("Installed " + kind + " custom resource does not serve supported API version "
                + group + "/" + version + "; usage and impact are incomplete");
    }

    @FunctionalInterface
    interface CustomObjectConsumer {
        void accept(Map<String, Object> item);
    }
}
