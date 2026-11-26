// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.ssl.dns.DnsValidationDomainService;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DnsValidationDomainServiceTest {

    private final DnsValidationDomainService service = new DnsValidationDomainService();

    @Test
    void buildCertificateDomains_dedupesAndPrunesWildcardCoveredHosts() {
        List<String> result = service.buildCertificateDomains(
                "example.com",
                false,
                List.of("*.example.com", "api.example.com", "www.example.com", "a.b.example.com", "*.foo.com"));

        assertThat(result).contains("example.com");
        assertThat(result).contains("*.example.com");
        assertThat(result).contains("*.foo.com");
        assertThat(result).contains("a.b.example.com");
        assertThat(result).doesNotContain("api.example.com");
        assertThat(result).doesNotContain("www.example.com");
    }

    @Test
    void toRecordDomain_stripsWildcardPrefix() {
        assertThat(service.toRecordDomain("*.example.com")).isEqualTo("example.com");
        assertThat(service.toRecordDomain("api.example.com")).isEqualTo("api.example.com");
    }
}
