// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DnsValidationDomainServiceTest {

    private final DnsValidationDomainService service = new DnsValidationDomainService();

    @Test
    void buildValidationDomains_filtersOneLevelSubdomainCoveredByWildcard() {
        List<String> result = service.buildValidationDomains("example.com", List.of("*.example.com", "api.example.com"));

        assertThat(result).containsExactly("example.com", "*.example.com");
    }

    @Test
    void buildCertificateDomains_keepsPrimaryWildcardAndPrunesCoveredHosts() {
        List<String> result = service.buildCertificateDomains(
                "example.com",
                true,
                List.of("api.example.com", "*.example.com", "www.example.com", "*.foo.example.com", "bar.foo.example.com"));

        assertThat(result).containsExactly("*.example.com", "example.com", "*.foo.example.com");
    }

    @Test
    void buildCertificateDomains_wildcardPrimary_includesTheApexAfterTheWildcard() {
        assertThat(service.buildCertificateDomains("example.com", true, List.of()))
                .containsExactly("*.example.com", "example.com");
    }

    @Test
    void buildCertificateDomains_wildcardPrimaryWithTheApexAsSan_listsTheApexOnce() {
        assertThat(service.buildCertificateDomains("example.com", true, List.of("example.com", "api.example.com")))
                .containsExactly("*.example.com", "example.com");
    }

    @Test
    void buildCertificateDomains_primaryWildcardTrue_withMixedSanPatterns() {
        List<String> result = service.buildCertificateDomains(
                "xyz.com",
                true,
                List.of("*.xyz.com", "xyz.xom", "api.xyz.com"));

        assertThat(result).containsExactly("*.xyz.com", "xyz.com", "xyz.xom");
    }

    @Test
    void buildCertificateDomains_primaryWildcardFalse_withMixedSanPatterns() {
        List<String> result = service.buildCertificateDomains(
                "xyz.com",
                false,
                List.of("*.xyz.com", "xyz.xom", "api.xyz.com"));

        assertThat(result).containsExactly("xyz.com", "*.xyz.com", "xyz.xom");
    }

    @Test
    void toRecordDomain_stripsWildcardPrefix() {
        assertThat(service.toRecordDomain("*.example.com")).isEqualTo("example.com");
        assertThat(service.toRecordDomain("api.example.com")).isEqualTo("api.example.com");
    }

    @Test
    void toRecordDomain_null_returnsNull() {
        assertThat(service.toRecordDomain(null)).isNull();
    }

    @Test
    void buildCertificateDomains_nullPrimary_throws() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> service.buildCertificateDomains(null, false, java.util.List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildCertificateDomains_emptyPrimary_throws() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> service.buildCertificateDomains("   ", false, java.util.List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildCertificateDomains_nullSanList_returnsPrimaryOnly() {
        List<String> result = service.buildCertificateDomains("example.com", false, null);
        assertThat(result).containsExactly("example.com");
    }

    @Test
    void buildCertificateDomains_normalizesAndDeduplicatesPrimaryEntry() {
        // San entry equals primary after normalize (trim, lowercase, strip trailing dot) → de-dupes
        List<String> result = service.buildCertificateDomains(
                "Example.COM.",
                false,
                List.of("  example.com.  ", "", "api.example.com"));
        assertThat(result).containsExactly("example.com", "api.example.com");
    }

    @Test
    void buildCertificateDomains_duplicateWildcardSan_isCollapsed() {
        // Same wildcard appearing twice should only show once
        List<String> result = service.buildCertificateDomains(
                "example.com", false, List.of("*.example.com", "*.example.com"));
        assertThat(result).containsExactly("example.com", "*.example.com");
    }

    // ── additional branch coverage ─────────────────────────────────────────

    @Test
    void buildCertificateDomains_emptySanInList_isSkipped() {
        List<String> result = service.buildCertificateDomains(
                "example.com", false, List.of("", "  ", "api.example.com"));
        assertThat(result).containsExactly("example.com", "api.example.com");
    }

    @Test
    void buildCertificateDomains_sanNormalizesToEmpty_isSkipped() {
        List<String> result = service.buildCertificateDomains(
                "example.com", false, java.util.Arrays.asList(null, "  ", "api.example.com"));
        assertThat(result).containsExactly("example.com", "api.example.com");
    }

    @Test
    void buildCertificateDomains_multiLevelSubdomainNotCoveredByWildcard() {
        // *.example.com covers ONE label — not "shop.api.example.com" (two labels).
        List<String> result = service.buildCertificateDomains(
                "example.com", false, List.of("*.example.com", "shop.api.example.com"));
        assertThat(result).containsExactly("example.com", "*.example.com", "shop.api.example.com");
    }

    @Test
    void buildCertificateDomains_bareBaseDomainNotCoveredByWildcard() {
        // *.example.com does NOT cover example.com itself — bare base isn't a one-label match.
        List<String> result = service.buildCertificateDomains(
                "other.com", false, List.of("*.example.com", "example.com"));
        assertThat(result).containsExactly("other.com", "*.example.com", "example.com");
    }

    @Test
    void buildCertificateDomains_sanEqualsPrimaryAfterWildcardPrefix_dedup() {
        // Wildcard primary + SAN identical after normalization
        List<String> result = service.buildCertificateDomains(
                "example.com", true, List.of("*.example.com"));
        assertThat(result).containsExactly("*.example.com", "example.com");
    }

    @Test
    void toRecordDomain_bareDomain_unchanged() {
        assertThat(service.toRecordDomain("example.com")).isEqualTo("example.com");
    }

    @Test
    void toRecordDomain_multiLabelWildcard_stripsOnlyPrefix() {
        assertThat(service.toRecordDomain("*.api.example.com")).isEqualTo("api.example.com");
    }

    @Test
    void buildCertificateDomains_primaryWithLeadingTrailingWhitespace_trimmedAndNormalized() {
        List<String> result = service.buildCertificateDomains(
                "  API.Example.COM.  ", false, List.of());
        assertThat(result).containsExactly("api.example.com");
    }

    @Test
    void buildCertificateDomains_wildcardSanAfterOneLabelSan_stillPrunesTheOneLabel() {
        // Order-invariance: the one-label host should still be pruned by the later wildcard.
        List<String> result = service.buildCertificateDomains(
                "example.com", false, List.of("api.example.com", "*.example.com"));
        // "api.example.com" is one label under *.example.com → pruned.
        assertThat(result).containsExactly("example.com", "*.example.com");
    }
}
