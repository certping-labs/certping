// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class SanPatternValidator implements ConstraintValidator<ValidSanPattern, String> {

    /**
     * Optionally prefixed with {@code *.}, then a valid FQDN (same rules as
     * {@link DomainValidator#PATTERN}).
     */
    static final Pattern PATTERN = Pattern.compile(
            "^(?:\\*\\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]{2,}$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext ctx) {
        if (value == null || value.isBlank()) {
            return true; // null/blank deferred to @NotBlank / @NotEmpty on the list
        }
        return PATTERN.matcher(value.strip()).matches();
    }
}
