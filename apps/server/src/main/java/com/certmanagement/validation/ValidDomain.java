// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Validates that a string is a well-formed, fully-qualified domain name.
 *
 * <p>Rules:
 * <ul>
 *   <li>At least two dot-separated labels (e.g. {@code example.com}, {@code sub.example.com}).</li>
 *   <li>Each label: 1–63 characters, {@code [a-zA-Z0-9-]}, must not start or end with a hyphen.</li>
 *   <li>No wildcard prefix — use {@link ValidSanPattern} for patterns that allow {@code *.}.</li>
 *   <li>{@code null} and blank values pass (pair with {@code @NotBlank} if required).</li>
 * </ul>
 */
@Documented
@Constraint(validatedBy = DomainValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidDomain {

    String message() default "must be a valid fully-qualified domain name (e.g. example.com, sub.example.com)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
