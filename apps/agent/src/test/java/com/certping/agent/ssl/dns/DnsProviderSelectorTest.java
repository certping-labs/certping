// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class DnsProviderSelectorTest {

    private final DnsProviderSelector selector = new DnsProviderSelector();

    @Test
    void selectProvider_exactMatch_usesSanProvider() {
        DnsProvider root = mock(DnsProvider.class);
        DnsProvider san = mock(DnsProvider.class);

        DnsProvider selected = selector.selectProvider(
                "api.example.com",
                "example.com",
                root,
                Map.of("api.example.com", san));

        assertThat(selected).isSameAs(san);
    }

    @Test
    void selectProvider_wildcardMatch_usesSanProvider() {
        DnsProvider root = mock(DnsProvider.class);
        DnsProvider san = mock(DnsProvider.class);

        DnsProvider selected = selector.selectProvider(
                "api.example.com",
                "example.com",
                root,
                Map.of("*.example.com", san));

        assertThat(selected).isSameAs(san);
    }

    @Test
    void selectProvider_noMatch_fallsBackToRootProvider() {
        DnsProvider root = mock(DnsProvider.class);
        DnsProvider san = mock(DnsProvider.class);

        DnsProvider selected = selector.selectProvider(
                "deep.api.example.com",
                "example.com",
                root,
                Map.of("*.example.com", san));

        assertThat(selected).isSameAs(root);
    }
}
