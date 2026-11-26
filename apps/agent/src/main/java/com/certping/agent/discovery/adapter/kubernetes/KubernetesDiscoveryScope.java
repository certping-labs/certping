// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.deployment.adapter.kubernetes.KubernetesAuthProvider;
import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;

import java.util.List;

record KubernetesDiscoveryScope(
        String authProvider,
        String clusterName,
        List<String> namespaces,
        boolean allNamespaces) {

    static final String ALL_NAMESPACES = "all_namespaces";

    static KubernetesDiscoveryScope fromJson(JsonNode root) {
        NamespaceSelection selection = parseNamespaceSelection(root.get("namespaces"));
        return new KubernetesDiscoveryScope(
                textValue(root.get("authProvider")),
                textValue(root.get("clusterName")),
                selection.namespaces(),
                selection.allNamespaces());
    }

    KubernetesAuthProvider parsedAuthProvider() {
        return KubernetesAuthProvider.fromConfigValue(authProvider);
    }

    List<String> explicitNamespaces() {
        if (allNamespaces) {
            return List.of();
        }
        return namespaces;
    }

    private static NamespaceSelection parseNamespaceSelection(JsonNode namespacesNode) {
        if (namespacesNode == null || namespacesNode.isNull()) {
            throw invalid("Kubernetes discovery scope must include namespaces. Use \"all_namespaces\" for cluster-wide discovery or an array of namespace names.");
        }
        if (namespacesNode.isString()) {
            String value = namespacesNode.asString().trim();
            if (ALL_NAMESPACES.equals(value)) {
                return new NamespaceSelection(List.of(), true);
            }
            throw invalid("Kubernetes discovery namespaces string mode only supports \"all_namespaces\"; use an array for explicit namespaces.");
        }

        if (!namespacesNode.isArray()) {
            throw invalid("Kubernetes discovery namespaces must be \"all_namespaces\" or an array of namespace names.");
        }
        if (namespacesNode.isEmpty()) {
            throw invalid("Kubernetes discovery namespaces array must contain at least one namespace.");
        }
        List<String> namespaces = parseExplicitNamespaces(namespacesNode);
        return new NamespaceSelection(namespaces, false);
    }

    private static String textValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isString()) {
            throw invalid("Kubernetes discovery scope values must be strings");
        }
        return node.asString();
    }

    private static List<String> parseExplicitNamespaces(JsonNode namespacesNode) {
        java.util.ArrayList<String> namespaces = new java.util.ArrayList<>();
        for (JsonNode item : namespacesNode) {
            if (item == null || item.isNull() || !item.isString()) {
                throw invalid("Kubernetes discovery namespaces entries must be strings.");
            }
            String namespace = item.asString().trim();
            if (namespace.isEmpty()) {
                throw invalid("Kubernetes discovery namespaces entries must be non-empty.");
            }
            if (ALL_NAMESPACES.equals(namespace)) {
                throw invalid("Use string form \"all_namespaces\" for all_namespaces mode.");
            }
            namespaces.add(namespace);
        }
        return namespaces.stream().distinct().sorted().toList();
    }

    private static PermanentAgentException invalid(String message) {
        return new PermanentAgentException("DISCOVERY_K8S_SCOPE_INVALID", message);
    }

    private record NamespaceSelection(List<String> namespaces, boolean allNamespaces) {
    }
}
