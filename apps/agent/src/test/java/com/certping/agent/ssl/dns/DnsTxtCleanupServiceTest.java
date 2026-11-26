// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.RetryableAgentException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class DnsTxtCleanupServiceTest {

    private final DnsTxtCleanupService cleanupService = new DnsTxtCleanupService();

    @Test
    void cleanup_continuesWhenOneDeleteFails() {
        DnsProvider first = mock(DnsProvider.class);
        DnsProvider second = mock(DnsProvider.class);

        doThrow(new RuntimeException("delete failed"))
                .when(first).deleteTxtRecord("_acme-challenge.example.com", "id-1");

        cleanupService.cleanup(List.of(
                new DnsTxtCleanupService.DnsTxtCleanupEntry(first, "_acme-challenge.example.com", "id-1"),
                new DnsTxtCleanupService.DnsTxtCleanupEntry(second, "_acme-challenge.api.example.com", "id-2")
        ));

        verify(first).deleteTxtRecord("_acme-challenge.example.com", "id-1");
        verify(second).deleteTxtRecord("_acme-challenge.api.example.com", "id-2");
    }

    @Test
    void cleanup_continuesWhenDeleteIsRetryable() {
        DnsProvider first = mock(DnsProvider.class);
        DnsProvider second = mock(DnsProvider.class);

        doThrow(new RetryableAgentException(
                "DNS_PROVIDER_THROTTLED",
                "dns cleanup was rate-limited",
                Duration.ofSeconds(60)))
                .when(first).deleteTxtRecord("_acme-challenge.example.com", "id-1");

        cleanupService.cleanup(List.of(
                new DnsTxtCleanupService.DnsTxtCleanupEntry(first, "_acme-challenge.example.com", "id-1"),
                new DnsTxtCleanupService.DnsTxtCleanupEntry(second, "_acme-challenge.api.example.com", "id-2")
        ));

        verify(first).deleteTxtRecord("_acme-challenge.example.com", "id-1");
        verify(second).deleteTxtRecord("_acme-challenge.api.example.com", "id-2");
    }
}
