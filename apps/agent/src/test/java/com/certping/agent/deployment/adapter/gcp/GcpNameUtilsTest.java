// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GcpNameUtilsTest {

    // ---- toResourceId ----

    @Test
    void toResourceId_typicalDomain_lowercaseWithHyphens() {
        assertThat(GcpNameUtils.toResourceId("api.example.com", "certping"))
                .isEqualTo("api-example-com");
    }

    @Test
    void toResourceId_upperCaseInput_lowercased() {
        assertThat(GcpNameUtils.toResourceId("API.Example.Com", "certping"))
                .isEqualTo("api-example-com");
    }

    @Test
    void toResourceId_underscoresConvertedToHyphens() {
        assertThat(GcpNameUtils.toResourceId("my_service_name", "certping"))
                .isEqualTo("my-service-name");
    }

    @Test
    void toResourceId_specialCharsStrippedAndCollapsed() {
        assertThat(GcpNameUtils.toResourceId("api@example!com", "certping"))
                .isEqualTo("api-example-com");
    }

    @Test
    void toResourceId_leadingAndTrailingHyphensStripped() {
        assertThat(GcpNameUtils.toResourceId("--api--", "certping"))
                .isEqualTo("api");
    }

    @Test
    void toResourceId_nullInput_returnsFallback() {
        assertThat(GcpNameUtils.toResourceId(null, "my-fallback"))
                .isEqualTo("my-fallback");
    }

    @Test
    void toResourceId_blankInput_returnsFallback() {
        assertThat(GcpNameUtils.toResourceId("   ", "my-fallback"))
                .isEqualTo("my-fallback");
    }

    @Test
    void toResourceId_nullBothArgs_returnsCertping() {
        assertThat(GcpNameUtils.toResourceId(null, null))
                .isEqualTo("certping");
    }

    @Test
    void toResourceId_inputReducesToEmpty_returnsCertping() {
        // all special chars, nothing left after sanitization
        assertThat(GcpNameUtils.toResourceId("!!!@@@###", null))
                .isEqualTo("certping");
    }

    @Test
    void toResourceId_longInput_trimmedTo63Chars() {
        String long63 = "a".repeat(70);
        assertThat(GcpNameUtils.toResourceId(long63, "certping"))
                .hasSize(63);
    }

    @Test
    void toResourceId_longInputEndingWithHyphen_trailingHyphenStripped() {
        // 62 'a' + '-' at position 63 — the trim should strip the trailing hyphen
        String input = "a".repeat(62) + "-more-chars";
        String result = GcpNameUtils.toResourceId(input, "certping");
        assertThat(result).doesNotEndWith("-");
        assertThat(result.length()).isLessThanOrEqualTo(63);
    }

    // ---- versionedId ----

    @Test
    void versionedId_appendsTimestampSuffix() {
        String result = GcpNameUtils.versionedId("api.example.com");
        // normalized base "api-example-com" + "-" + 14-digit timestamp
        assertThat(result).startsWith("api-example-com-");
        // suffix is exactly 14 digits (yyyyMMddHHmmss)
        String suffix = result.substring("api-example-com-".length());
        assertThat(suffix).matches("\\d{14}");
    }

    @Test
    void versionedId_resultDoesNotExceed63Chars() {
        String longBase = "a".repeat(60);
        assertThat(GcpNameUtils.versionedId(longBase)).hasSizeLessThanOrEqualTo(63);
    }

    @Test
    void versionedId_nullBase_usesDefaultNormalization() {
        // null base normalises to "certping" via toResourceId
        String result = GcpNameUtils.versionedId(null);
        assertThat(result).startsWith("certping-");
    }

    // ---- deriveBaseName ----

    @Test
    void deriveBaseName_simpleDomainAndXref_combinesWithSuffix() {
        String result = GcpNameUtils.deriveBaseName("api.example.com", "abc1234567890");
        // domain-part-xrefsuffix(last 10 of 13)
        assertThat(result).startsWith("api-example-com-");
        assertThat(result).endsWith("c1234567890".substring(1));
    }

    @Test
    void deriveBaseName_nullXref_returnsOnlyDomain() {
        String result = GcpNameUtils.deriveBaseName("api.example.com", null);
        assertThat(result).isEqualTo("api-example-com");
    }

    @Test
    void deriveBaseName_blankXref_returnsOnlyDomain() {
        String result = GcpNameUtils.deriveBaseName("api.example.com", "");
        assertThat(result).isEqualTo("api-example-com");
    }

    @Test
    void deriveBaseName_xrefAllSpecialChars_stripsToEmpty_returnsOnlyDomain() {
        // No alphanumeric in xref → suffix is empty → no separator added
        String result = GcpNameUtils.deriveBaseName("api.example.com", "!!!");
        assertThat(result).isEqualTo("api-example-com");
    }

    @Test
    void deriveBaseName_xrefUpperCase_lowercased() {
        String result = GcpNameUtils.deriveBaseName("api.example.com", "ABCDEFGH12");
        assertThat(result).endsWith("-abcdefgh12");
    }

    @Test
    void deriveBaseName_nullDomain_usesCertFallback() {
        String result = GcpNameUtils.deriveBaseName(null, "abcdef1234");
        assertThat(result).isEqualTo("cert-abcdef1234");
    }

    @Test
    void deriveBaseName_longResult_trimmedToBaseLength() {
        String longDomain = "a".repeat(80);
        String result = GcpNameUtils.deriveBaseName(longDomain, "abcdef1234");
        assertThat(result.length()).isLessThanOrEqualTo(48);
    }
}
