// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentInfo;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Puts a reported {@link AgentInfo} into its fixed shape before it is stored or shown. Each value
 * must match a narrow pattern for its field (a version, a host name, an enum name); anything else,
 * and anything that looks like a token or a key, is dropped. The agent is trusted to say what it
 * is, not to put arbitrary text on an admin page.
 */
public final class AgentInfoSanitizer {

    static final Set<String> SECRET_STORES = Set.of("LOCAL", "AZURE_KV", "AWS_SECRETS_MANAGER", "GCP_SECRET_MANAGER");

    private static final Pattern VERSION = Pattern.compile("[0-9A-Za-z][0-9A-Za-z._+-]{0,63}");
    private static final Pattern HOSTNAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,252}");
    private static final Pattern OS = Pattern.compile("[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}");
    private static final Pattern CAPABILITY = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");
    private static final int MAX_CAPABILITIES = 64;
    private static final int MAX_JOBS = 10_000;

    private AgentInfoSanitizer() {
    }

    /** A clean copy, or null for no info. */
    public static AgentInfo sanitize(AgentInfo in) {
        if (in == null) {
            return null;
        }
        AgentInfo.Capabilities caps = in.getCapabilities();
        String store = in.getSecretStore() == null ? null : in.getSecretStore().trim().toUpperCase(Locale.ROOT);
        Integer jobs = in.getMaxConcurrentJobs();
        return AgentInfo.builder()
                .version(text(in.getVersion(), VERSION))
                .hostname(text(in.getHostname(), HOSTNAME))
                .os(text(in.getOs(), OS))
                .javaVersion(text(in.getJavaVersion(), VERSION))
                .secretStore(store != null && SECRET_STORES.contains(store) ? store : null)
                .maxConcurrentJobs(jobs != null && jobs >= 1 && jobs <= MAX_JOBS ? jobs : null)
                .proxyConfigured(in.getProxyConfigured())
                .bundled(in.getBundled())
                .capabilities(AgentInfo.Capabilities.builder()
                        .deploymentTargets(names(caps == null ? null : caps.getDeploymentTargets()))
                        .discoveryTargets(names(caps == null ? null : caps.getDiscoveryTargets()))
                        .dnsProviders(names(caps == null ? null : caps.getDnsProviders()))
                        .build())
                .build();
    }

    static String text(String value, Pattern pattern) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || looksSecret(trimmed) || !pattern.matcher(trimmed).matches()) {
            return null;
        }
        return trimmed;
    }

    private static List<String> names(List<String> values) {
        if (values == null) {
            return List.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String value : values) {
            String clean = text(value, CAPABILITY);
            if (clean != null && out.size() < MAX_CAPABILITIES) {
                out.add(clean);
            }
        }
        return new ArrayList<>(out);
    }

    /** An agent token or anything key-shaped is never a version, a host or a capability. */
    static boolean looksSecret(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.contains("cpa_") || lower.contains("-----begin") || lower.contains("private key");
    }
}
