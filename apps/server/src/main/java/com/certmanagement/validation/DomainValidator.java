// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class DomainValidator implements ConstraintValidator<ValidDomain, String> {

    /**
     * One or more labels of 1–63 chars ([a-zA-Z0-9], may contain hyphens but not at
     * start/end), each followed by a dot, then a TLD of at least 2 chars.
     * Single-label names (e.g. {@code localhost}) are rejected.
     */
    static final Pattern PATTERN = Pattern.compile(
            "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]{2,}$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext ctx) {
        if (value == null || value.isBlank()) {
            return true; // null/blank deferred to @NotBlank
        }
        return PATTERN.matcher(value.strip()).matches();
    }
}
