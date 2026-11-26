// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import java.util.Arrays;
import java.util.Locale;

/** Which part of a request {@link ClientAddressResolver} believes about the client ({@code certping.client-ip.source}). */
public enum ClientIpSource {

    /**
     * {@code X-Azure-ClientIP}, only when {@code X-Azure-FDID} is the configured Front Door profile id;
     * otherwise {@link #LAST_PROXY_HOP}.
     */
    FRONT_DOOR,

    /**
     * The rightmost {@code X-Forwarded-For} entry, which the last proxy appended itself, when the request
     * arrived from a private or loopback address; otherwise that address.
     */
    LAST_PROXY_HOP,

    /**
     * {@link jakarta.servlet.ServletRequest#getRemoteAddr()}, unchanged. This is <em>not</em> always the
     * socket peer. In Kubernetes, Spring Boot turns on Tomcat's {@code RemoteIpValve}, which has already
     * replaced it with an address taken from {@code X-Forwarded-For}: the rightmost entry that is not a
     * private address, or the leftmost one when all are private. Behind a source-NATing load balancer that
     * is a node IP.
     * The valve stays on, because OAuth2/OIDC redirect URIs depend on its {@code X-Forwarded-Proto}
     * handling.
     */
    PEER;

    /**
     * Reads a configured value, ignoring case and accepting {@code -} for {@code _}; blank is
     * {@link #LAST_PROXY_HOP}.
     *
     * @throws IllegalArgumentException for anything else, so a typo fails the start instead of
     *                                  silently trusting a different header
     */
    public static ClientIpSource parse(String value) {
        if (value == null || value.isBlank()) {
            return LAST_PROXY_HOP;
        }
        String name = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return Arrays.stream(values())
                .filter(source -> source.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("certping.client-ip.source must be one of "
                        + Arrays.toString(values()) + ", not '" + value + "'"));
    }
}
