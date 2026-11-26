// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import java.util.regex.Pattern;

/**
 * Centralises the "safe to log" view of upstream failures for Kubernetes deployment flows.
 *
 * <p>The agent still needs provider and API details locally for debugging, but those details should
 * be bounded and scrubbed before they are copied into structured logs or bubbled back to the server.
 */
public final class KubernetesErrorSanitizer {

    private static final int UPSTREAM_LOG_SNIPPET_LIMIT = 512;
    private static final Pattern SENSITIVE_UPSTREAM_FIELDS = Pattern.compile(
            "(?i)(\"?(token|access_token|refresh_token|authorization|clientSecret|client-secret|password|secret|client-certificate-data|client-key-data)\"?\\s*[:=]\\s*\")([^\"]+)(\")");

    private KubernetesErrorSanitizer() {
    }

    public static String redactAndBound(String upstreamText) {
        if (upstreamText == null || upstreamText.isBlank()) {
            return "<empty>";
        }

        String normalized = upstreamText.replaceAll("\\s+", " ").trim();
        String redacted = SENSITIVE_UPSTREAM_FIELDS.matcher(normalized).replaceAll("$1[REDACTED]$4");
        if (redacted.length() <= UPSTREAM_LOG_SNIPPET_LIMIT) {
            return redacted;
        }
        return redacted.substring(0, UPSTREAM_LOG_SNIPPET_LIMIT) + "...";
    }
}
