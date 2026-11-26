// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.messaging.model.DiscoveryFailedScope;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The parts of a discovery scan the agent could not read, and which stored certificates they
 * cover. A covered certificate the scan did not see is left as it was, never marked MISSING.
 *
 * <p>Matching uses the certificate's {@code resourceId}: an ACM ARN
 * ({@code arn:aws:acm:<region>:<account>:certificate/<id>}), a Key Vault id
 * ({@code https://<vault>.vault.azure.net/...}) or a Kubernetes id
 * ({@code k8s://<cluster>/<namespace>/...}). A scope of a type this server does not know, or a
 * blank scope id, covers every certificate: when in doubt nothing is marked MISSING.
 */
public final class FailedScopes {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private FailedScopes() {
    }

    /** {@code current} and {@code more}, without repeats (same type and id), in arrival order. */
    public static List<DiscoveryFailedScope> merge(Collection<DiscoveryFailedScope> current,
                                                   Collection<DiscoveryFailedScope> more) {
        Map<String, DiscoveryFailedScope> merged = new LinkedHashMap<>();
        for (Collection<DiscoveryFailedScope> source : List.of(
                current == null ? List.<DiscoveryFailedScope>of() : current,
                more == null ? List.<DiscoveryFailedScope>of() : more)) {
            for (DiscoveryFailedScope scope : source) {
                if (scope != null) {
                    merged.putIfAbsent(scope.getScopeType() + "\n" + scope.getScopeId(), scope);
                }
            }
        }
        return new ArrayList<>(merged.values());
    }

    /** The stored form (discovery_scan.failed_scopes); null for none. */
    public static String toJson(List<DiscoveryFailedScope> scopes) {
        return scopes == null || scopes.isEmpty() ? null : JSON.writeValueAsString(scopes);
    }

    /** The stored form read back; empty for none. Unreadable JSON reads as one scope covering everything. */
    public static List<DiscoveryFailedScope> fromJson(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            List<DiscoveryFailedScope> scopes = JSON.readValue(json, new TypeReference<List<DiscoveryFailedScope>>() { });
            return scopes == null ? List.of() : scopes;
        } catch (RuntimeException e) {
            return List.of(DiscoveryFailedScope.builder().scopeType("UNREADABLE").build());
        }
    }

    /** True when any of {@code scopes} covers the certificate at {@code resourceId}. */
    public static boolean coversAny(List<DiscoveryFailedScope> scopes, String resourceId) {
        return scopes.stream().anyMatch(scope -> covers(scope, resourceId));
    }

    static boolean covers(DiscoveryFailedScope scope, String resourceId) {
        String type = scope.getScopeType() == null ? "" : scope.getScopeType().trim().toUpperCase(Locale.ROOT);
        String id = scope.getScopeId() == null ? "" : scope.getScopeId().trim();
        if (id.isEmpty() || resourceId == null) {
            return true;
        }
        return switch (type) {
            case DiscoveryFailedScope.AWS_ACCOUNT -> id.equals(arnPart(resourceId, 4));
            case DiscoveryFailedScope.AWS_REGION -> coversRegion(id, resourceId);
            case DiscoveryFailedScope.AZURE_VAULT -> id.equalsIgnoreCase(vaultName(resourceId));
            case DiscoveryFailedScope.K8S_NAMESPACE -> id.equals(k8sPart(resourceId, 1));
            case DiscoveryFailedScope.K8S_CLUSTER -> id.equals(k8sPart(resourceId, 0));
            default -> true;
        };
    }

    private static boolean coversRegion(String id, String resourceId) {
        int slash = id.indexOf('/');
        String account = slash < 0 ? null : id.substring(0, slash);
        String region = slash < 0 ? id : id.substring(slash + 1);
        return region.equalsIgnoreCase(arnPart(resourceId, 3))
                && (account == null || account.isEmpty() || account.equals(arnPart(resourceId, 4)));
    }

    /** Part {@code index} of an ARN ({@code arn:partition:service:region:account:resource}), or null. */
    static String arnPart(String arn, int index) {
        if (!arn.startsWith("arn:")) {
            return null;
        }
        String[] parts = arn.split(":", 6);
        return parts.length > index ? parts[index] : null;
    }

    /** The vault of a Key Vault id such as {@code https://my-vault.vault.azure.net/certificates/x}, or null. */
    static String vaultName(String resourceId) {
        try {
            String host = URI.create(resourceId).getHost();
            if (host == null) {
                return null;
            }
            int dot = host.indexOf('.');
            return dot < 0 ? host : host.substring(0, dot);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Segment {@code index} after {@code k8s://} (0 the cluster, 1 the namespace), or null. */
    static String k8sPart(String resourceId, int index) {
        if (!resourceId.startsWith("k8s://")) {
            return null;
        }
        String[] parts = resourceId.substring("k8s://".length()).split("/");
        return parts.length > index ? parts[index] : null;
    }
}
