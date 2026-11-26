// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import com.certmanagement.utils.NetworkAddresses;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.function.Predicate;

/**
 * HTTP clients for URLs an organization admin configures (Teams and Slack webhooks, a ServiceNow instance).
 * Every address a host resolves to is checked in the resolver the connection itself uses, so a private,
 * loopback, link-local (the cloud metadata endpoint 169.254.169.254), carrier-grade NAT or unique-local
 * address is refused at connect time, also when DNS answers differently than it did when the URL was saved
 * (DNS rebinding). Redirects are never followed and nothing is retried.
 *
 * <p>{@code app.integrations.allow-private-addresses=true} lifts the address check, for installations
 * that post to a ServiceNow (or other endpoint) on their own network.
 */
public final class GuardedHttpClients {

    private GuardedHttpClients() {
    }

    /** Thrown from the resolver for a refused address; an {@link UnknownHostException} so the client fails the connect. */
    public static final class BlockedAddressException extends UnknownHostException {
        public BlockedAddressException(String host) {
            super("Refused to connect to " + host + ": it resolves to a private or internal address");
        }
    }

    public static HttpComponentsClientHttpRequestFactory requestFactory(Duration connectTimeout, Duration readTimeout,
                                                                        boolean allowPrivateAddresses) {
        return new HttpComponentsClientHttpRequestFactory(httpClient(connectTimeout, readTimeout,
                allowPrivateAddresses ? address -> false : NetworkAddresses::isNonPublic));
    }

    static CloseableHttpClient httpClient(Duration connectTimeout, Duration readTimeout,
                                          Predicate<InetAddress> blockedAddress) {
        DnsResolver guardedResolver = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                InetAddress[] addresses = SystemDefaultDnsResolver.INSTANCE.resolve(host);
                for (InetAddress address : addresses) {
                    if (blockedAddress.test(address)) {
                        throw new BlockedAddressException(host);
                    }
                }
                return addresses;
            }

            @Override
            public String resolveCanonicalHostname(String host) throws UnknownHostException {
                return SystemDefaultDnsResolver.INSTANCE.resolveCanonicalHostname(host);
            }
        };
        return HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setDnsResolver(guardedResolver)
                        .setDefaultConnectionConfig(ConnectionConfig.custom()
                                .setConnectTimeout(Timeout.of(connectTimeout))
                                .setSocketTimeout(Timeout.of(readTimeout))
                                .build())
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.of(connectTimeout))
                        .setResponseTimeout(Timeout.of(readTimeout))
                        .build())
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .disableCookieManagement()
                .build();
    }
}
