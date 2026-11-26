// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class SanPatternValidatorTest {

    private final SanPatternValidator validator = new SanPatternValidator();

    // ── Valid patterns ─────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "example.com",
            "*.example.com",
            "auto.example.pro",
            "*.auto.example.pro",
            "example.tech",
            "*.example.tech",
            "app.auto.example.pro",
            "example.pro",
            "*.example.pro"
    })
    void valid_acceptsFqdnsAndSingleLabelWildcards(String pattern) {
        assertThat(validator.isValid(pattern, null)).isTrue();
    }

    // ── Null / blank pass through ──────────────────────────────────────────────

    @Test
    void valid_nullPassesThrough() {
        assertThat(validator.isValid(null, null)).isTrue();
    }

    @Test
    void valid_blankPassesThrough() {
        assertThat(validator.isValid("  ", null)).isTrue();
    }

    // ── Invalid patterns ───────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "localhost",             // single label
            "*.*.example.com",       // double wildcard
            "*example.com",          // infix wildcard (no dot after *)
            ".example.com",          // leading dot
            "example.com.",          // trailing dot
            "-bad.example.com",      // label starts with hyphen
            "exam ple.com",          // space
            "*.localhost"            // wildcard over single label (no dot in base)
    })
    void invalid_rejectsMalformedPatterns(String pattern) {
        assertThat(validator.isValid(pattern, null)).isFalse();
    }

    // ── Canonical SAN patterns must all pass ───────────────────────────────────

    @Test
    void valid_canonicalFiveDomainSet() {
        String[] canonical = {
                "*.auto.example.pro",
                "example.pro",
                "*.example.pro",
                "example.tech",
                "*.example.tech"
        };
        for (String p : canonical) {
            assertThat(validator.isValid(p, null))
                    .as("expected valid: %s", p)
                    .isTrue();
        }
    }
}
