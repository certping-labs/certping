// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.exception.BadRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @Test
    void accepts_minimal_strong_password() {
        assertThatCode(() -> policy.validate("Aa1@aaaa", null, null))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Aa1@", "Aa1@aa"}) // <8 chars
    void rejects_too_short(String pw) {
        assertThatThrownBy(() -> policy.validate(pw, null, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("at least 8 characters");
    }

    @Test
    void rejects_too_long_over_100_chars() {
        String pw = "A1@" + "a".repeat(120);
        assertThatThrownBy(() -> policy.validate(pw, null, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("no more than 100");
    }

    @Test
    void rejects_no_uppercase() {
        assertThatThrownBy(() -> policy.validate("aaaa1@aa", null, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("uppercase");
    }

    @Test
    void rejects_no_digit() {
        assertThatThrownBy(() -> policy.validate("AAaa@@aa", null, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("digit");
    }

    @Test
    void rejects_no_special() {
        assertThatThrownBy(() -> policy.validate("AAaa11aa", null, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("special character");
    }

    @Test
    void rejects_password_containing_username() {
        assertThatThrownBy(() -> policy.validate("Alice123@x", "alice", null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("username");
    }

    @Test
    void rejects_password_containing_email_local_part() {
        assertThatThrownBy(() -> policy.validate("Bobby123@x", null, "bobby@example.com"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("email");
    }

    @Test
    void short_email_local_part_does_not_trip_substring_check() {
        // local-part "ab" is <3 chars; substring check is skipped to avoid false positives.
        assertThatCode(() -> policy.validate("Strong1@Aa", null, "ab@example.com"))
                .doesNotThrowAnyException();
    }

    @Test
    void null_password_rejected_as_too_short() {
        assertThatThrownBy(() -> policy.validate(null, null, null))
                .isInstanceOf(BadRequestException.class);
    }
}
