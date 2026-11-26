// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for CloudflareDnsProvider constructor and credential validation.
 * HTTP behaviour is tested via WireMock in integration tests.
 */
class CloudflareDnsProviderTest {

    @Test
    void constructor_nullToken_throwsPermanentException() {
        assertThatThrownBy(() -> new CloudflareDnsProvider(null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> {
                    var pae = (PermanentAgentException) e;
                    org.assertj.core.api.Assertions.assertThat(pae.getErrorCode())
                            .isEqualTo("DNS_CREDENTIAL_INVALID");
                });
    }

    @Test
    void constructor_blankToken_throwsPermanentException() {
        assertThatThrownBy(() -> new CloudflareDnsProvider("   "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> {
                    var pae = (PermanentAgentException) e;
                    org.assertj.core.api.Assertions.assertThat(pae.getErrorCode())
                            .isEqualTo("DNS_CREDENTIAL_INVALID");
                });
    }

    @Test
    void constructor_validToken_doesNotThrow() {
        // No exception expected
        new CloudflareDnsProvider("valid-token-abc");
    }

    @Test
    void deleteTxtRecord_markerRecordId_doesNotThrow() {
        // "existing-" prefix records are silently skipped (no HTTP call)
        CloudflareDnsProvider provider = new CloudflareDnsProvider("valid-token");
        // Should complete without throwing even though no HTTP call is made
        provider.deleteTxtRecord("_acme-challenge.example.com", "existing-_acme-challenge.example.com");
    }
}
