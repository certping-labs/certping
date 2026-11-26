// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertDeploymentMessage;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Shared helpers for GCP deployment adapters: domain/name resolution, certificate list merging, config JSON.
 */
@Slf4j
public final class GcpDeploymentSupport {

    private GcpDeploymentSupport() {}

    /**
     * Read the prior {@code certificateResourceName} (or other named field) from the per-cert
     * result JSON carried on {@link CertDeploymentMessage#getConfigJson()}. Returns null if the
     * config is empty, unparseable, or missing the field — callers treat null as "first deploy".
     */
    public static String readPriorCertResourceName(ObjectMapper objectMapper,
                                                   String configJson,
                                                   String fieldName) {
        if (configJson == null || configJson.isBlank()) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode val = root.get(fieldName);
            if (val != null && val.isString() && !val.asString().isBlank()) {
                return val.asString();
            }
        } catch (Exception e) {
            log.warn("GCP adapter: failed to parse prior result configJson — treating as first deploy: {}",
                    e.getMessage());
        }
        return null;
    }

    public static void requireDeploymentHandle(String handle, String contextLabel) {
        if (handle == null || handle.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_MISSING",
                    "deploymentCredHandle is required for " + contextLabel + " deployments");
        }
    }

    public static String resolveDomain(CertDeploymentMessage message,
                                       CertificateBundle bundle,
                                       String contextLabel) {
        String fromMessage = CertificateIdentityUtils.normaliseDomain(message.getDomain());
        if (!fromMessage.isBlank()) {
            return fromMessage;
        }
        return CertificateIdentityUtils.extractPrimaryDomainFromPem(bundle.leafCertificate())
                .orElseThrow(() -> new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                        contextLabel + " deployment requires domain in the message or a parsable leaf certificate"));
    }

    public static String resolveCertificateBaseName(String domain,
                                                    Map<String, String> domainCertificateNames,
                                                    String certificateName) {
        if (domain != null && domainCertificateNames != null) {
            String mapped = domainCertificateNames.get(domain);
            if (mapped != null && !mapped.isBlank()) {
                return mapped.trim();
            }
        }
        if (certificateName != null && !certificateName.isBlank()) {
            return certificateName.trim();
        }
        return null;
    }

    public static String resolveHostname(String explicitHostname, String domain) {
        if (explicitHostname != null && !explicitHostname.isBlank()) {
            return explicitHostname.trim();
        }
        return domain;
    }

    public static List<String> mergeCertificateLists(String newCertResourceName, List<String> existing) {
        return mergeCertificateLists(newCertResourceName, existing, null);
    }

    /**
     * Merge the new cert resource into the proxy's existing list, optionally excluding a prior
     * resource that's about to be deleted. The new cert is placed first; duplicates are dropped.
     */
    public static List<String> mergeCertificateLists(String newCertResourceName,
                                                     List<String> existing,
                                                     String priorToRemove) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        if (newCertResourceName != null && !newCertResourceName.isBlank()) {
            merged.add(newCertResourceName);
        }
        if (existing != null) {
            for (String cert : existing) {
                if (cert == null || cert.isBlank()) continue;
                if (priorToRemove != null && cert.equals(priorToRemove)) continue;
                merged.add(cert);
            }
        }
        return List.copyOf(merged);
    }

    /** The desired proxy cert list plus the superseded resources to delete afterwards. */
    public record CertificatePrune(List<String> desired, List<String> toDelete) {}

    /**
     * Lineage-aware version of {@link #mergeCertificateLists}. Compute {@code SslCertificate}s are
     * immutable, so every deploy creates a new {@code {baseName}-{yyyyMMddHHmmss}} resource. Relying
     * only on the single {@code priorToRemove} tracked in configJson leaks the prior resources
     * whenever that config isn't threaded back (first deploy of a lineage, a partially-failed
     * deploy, etc.) — and on a proxy shared by many certs those leaks pile up until the project hits
     * the per-project SSL-certificate quota.
     *
     * <p>This keeps the new cert plus every unrelated cert (other domains / other {@code xref}
     * lineages) and marks for deletion <b>all</b> stale versions of <em>this</em> lineage — i.e.
     * every existing cert whose short name is {@code {lineageBaseName}-{14-digit-timestamp}} — as
     * well as the explicit {@code priorToRemove} (covers cross-renewal names that use a different
     * base). Other domains are never touched, so SNI on a shared proxy keeps working.
     *
     * @param newCertResourceName the freshly created cert (full self-link or partial resource name)
     * @param existing            the proxy's current cert list
     * @param lineageBaseName     {@code deriveBaseName(domain, xref)} — the stable lineage key
     * @param priorToRemove       the prior cert from configJson, or null
     */
    public static CertificatePrune mergeAndPruneByLineage(String newCertResourceName,
                                                          List<String> existing,
                                                          String lineageBaseName,
                                                          String priorToRemove) {
        LinkedHashSet<String> desired = new LinkedHashSet<>();
        List<String> toDelete = new ArrayList<>();
        if (newCertResourceName != null && !newCertResourceName.isBlank()) {
            desired.add(newCertResourceName);
        }
        String newShort = shortResourceName(newCertResourceName);
        String priorShort = shortResourceName(priorToRemove);
        boolean priorSeen = false;
        if (existing != null) {
            for (String cert : existing) {
                if (cert == null || cert.isBlank()) continue;
                if (cert.equals(newCertResourceName)) continue; // already the newest, keep once
                String certShort = shortResourceName(cert);
                boolean sameLineage = lineageBaseName != null
                        && isVersionedSibling(certShort, lineageBaseName);
                // Compare by bare cert name so a full self-link and a partial resource name
                // (projects/.../sslCertificates/NAME) for the same cert still match.
                boolean isPrior = priorShort != null && priorShort.equals(certShort);
                if (sameLineage || isPrior) {
                    toDelete.add(cert); // superseded version of THIS cert — prune it
                    priorSeen |= isPrior;
                } else {
                    desired.add(cert); // a different cert / domain — leave it in place
                }
            }
        }
        // Always retire the tracked prior, even if it's already detached from the proxy — an
        // orphaned compute SslCertificate still counts against the per-project quota. Skip when the
        // prior is the same resource as the new cert (a no-op redeploy).
        if (priorShort != null && !priorSeen && !priorShort.equals(newShort)) {
            toDelete.add(priorToRemove);
        }
        return new CertificatePrune(List.copyOf(desired), List.copyOf(toDelete));
    }

    /** Last path segment of a full self-link or partial resource name (the bare cert name). */
    private static String shortResourceName(String resourceUrlOrName) {
        if (resourceUrlOrName == null || resourceUrlOrName.isBlank()) {
            return null;
        }
        int slash = resourceUrlOrName.lastIndexOf('/');
        return slash >= 0 ? resourceUrlOrName.substring(slash + 1) : resourceUrlOrName;
    }

    /**
     * True when {@code shortName} is {@code baseName-<yyyyMMddHHmmss>} — a versioned sibling minted
     * by {@link GcpNameUtils#versionedId(String)} for the same lineage. The 14-digit-timestamp check
     * avoids false positives where one base name is a prefix of another.
     */
    private static boolean isVersionedSibling(String shortName, String baseName) {
        String prefix = baseName + "-";
        if (!shortName.startsWith(prefix)) {
            return false;
        }
        String suffix = shortName.substring(prefix.length());
        if (suffix.length() != 14) {
            return false;
        }
        for (int i = 0; i < suffix.length(); i++) {
            if (!Character.isDigit(suffix.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Result for a target-proxy deploy that went through the proxy's certificate map. Keeps the
     * {@code certificateName} key the proxy adapters read back as the prior certificate.
     */
    public static String proxyMapResultConfigJson(ObjectMapper objectMapper,
                                                  GcpCertificateMapDeployer.MapDeployment deployment) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("certificateName", deployment.certificateResourceName());
        payload.put("certificateMap", deployment.certificateMap());
        payload.put("appliedEntries", deployment.appliedEntries());
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{\"certificateName\":\"" + deployment.certificateResourceName() + "\"}";
        }
    }

    public static String targetProxyResultConfigJson(ObjectMapper objectMapper,
                                                     String certificateResourceName,
                                                     String targetProxyName,
                                                     String mapEntryName,
                                                     String hostname) {
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("certificateResourceName", certificateResourceName);
        payload.put("targetProxyName", targetProxyName);
        if (mapEntryName != null && !mapEntryName.isBlank()) {
            payload.put("certificateMapEntryName", mapEntryName);
        }
        if (hostname != null && !hostname.isBlank()) {
            payload.put("hostname", hostname);
        }
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{\"certificateResourceName\":\"" + certificateResourceName + "\"}";
        }
    }

    public static String certificateManagerResultConfigJson(ObjectMapper objectMapper,
                                                            String certificateResourceName,
                                                            String certificateMapName,
                                                            String mapEntryName,
                                                            String hostname) {
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("certificateResourceName", certificateResourceName);
        if (certificateMapName != null && !certificateMapName.isBlank()) {
            payload.put("certificateMapName", certificateMapName);
        }
        if (mapEntryName != null && !mapEntryName.isBlank()) {
            payload.put("certificateMapEntryName", mapEntryName);
        }
        if (hostname != null && !hostname.isBlank()) {
            payload.put("hostname", hostname);
        }
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{\"certificateResourceName\":\"" + certificateResourceName + "\"}";
        }
    }
}
