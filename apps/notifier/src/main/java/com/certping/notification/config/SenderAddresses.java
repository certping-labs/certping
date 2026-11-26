// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import java.net.URI;
import java.util.Locale;

/**
 * The address notification email is sent from. An install sets EMAIL_FROM; when it does not, the
 * address is no-reply at the host of the install's public URL (CERTPING_URL), so mail never claims
 * to come from a domain the install does not own.
 */
public final class SenderAddresses {

    private SenderAddresses() {
    }

    /**
     * The configured address when there is one, otherwise no-reply at the host of {@code baseUrl},
     * otherwise null.
     */
    public static String resolve(String configured, String baseUrl) {
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        String host = host(baseUrl);
        return host == null ? null : "no-reply@" + host;
    }

    private static String host(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return null;
        }
        try {
            String host = URI.create(baseUrl.trim()).getHost();
            if (host == null || host.isBlank()) {
                return null;
            }
            if (host.startsWith("[")) {
                return null;
            }
            return host.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
