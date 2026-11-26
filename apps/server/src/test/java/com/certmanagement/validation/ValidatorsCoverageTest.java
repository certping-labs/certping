// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.validation.ConstraintValidatorContext;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class ValidatorsCoverageTest {

    @Mock
    ConstraintValidatorContext ctx;

    @Test
    void domainValidator() {
        DomainValidator v = new DomainValidator();
        // null/blank deferred -> true
        assertThat(v.isValid(null, ctx)).isTrue();
        assertThat(v.isValid("   ", ctx)).isTrue();
        // valid domains
        assertThat(v.isValid("example.com", ctx)).isTrue();
        assertThat(v.isValid(" sub.example.co.uk ", ctx)).isTrue();
        assertThat(v.isValid("a-b.example.com", ctx)).isTrue();
        // invalid: single label, leading dot, wildcard
        assertThat(v.isValid("localhost", ctx)).isFalse();
        assertThat(v.isValid("-bad.com", ctx)).isFalse();
        assertThat(v.isValid("*.example.com", ctx)).isFalse();
    }

    @Test
    void sanPatternValidator() {
        SanPatternValidator v = new SanPatternValidator();
        assertThat(v.isValid(null, ctx)).isTrue();
        assertThat(v.isValid("", ctx)).isTrue();
        // valid: plain fqdn and wildcard prefix
        assertThat(v.isValid("example.com", ctx)).isTrue();
        assertThat(v.isValid("*.example.com", ctx)).isTrue();
        assertThat(v.isValid(" *.sub.example.org ", ctx)).isTrue();
        // invalid
        assertThat(v.isValid("localhost", ctx)).isFalse();
        assertThat(v.isValid("**.example.com", ctx)).isFalse();
    }
}
