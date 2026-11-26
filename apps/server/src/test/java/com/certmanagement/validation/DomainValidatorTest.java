// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class DomainValidatorTest {

    private final DomainValidator validator = new DomainValidator();

    // ── Valid domains ──────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "example.com",
            "auto.example.pro",
            "app.auto.example.pro",
            "example.tech",
            "my-domain.example.com",
            "xn--nxasmq6b.com",  // punycode
            "a.io"
    })
    void valid_acceptsWellFormedFqdns(String domain) {
        assertThat(validator.isValid(domain, null)).isTrue();
    }

    // ── Null / blank pass through (deferred to @NotBlank) ─────────────────────

    @Test
    void valid_nullPassesThrough() {
        assertThat(validator.isValid(null, null)).isTrue();
    }

    @Test
    void valid_blankPassesThrough() {
        assertThat(validator.isValid("   ", null)).isTrue();
    }

    // ── Invalid domains ────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "localhost",             // single label
            ".example.com",          // leading dot
            "example.com.",          // trailing dot
            "example..com",          // consecutive dots
            "-example.com",          // label starts with hyphen
            "example-.com",          // label ends with hyphen
            "*.example.com",         // wildcard — use @ValidSanPattern instead
            "exam ple.com",          // space
            ""                       // empty string (treated as blank → isValid passes, but @NotBlank rejects)
    })
    void invalid_rejectsNonFqdnStrings(String domain) {
        // empty string is blank, isValid returns true and @NotBlank handles it
        if (domain.isBlank()) {
            assertThat(validator.isValid(domain, null)).isTrue();
        } else {
            assertThat(validator.isValid(domain, null)).isFalse();
        }
    }
}
