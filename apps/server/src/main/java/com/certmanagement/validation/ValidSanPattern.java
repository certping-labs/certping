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
 * Validates that a string is either a valid FQDN or a single-label wildcard pattern.
 *
 * <p>Accepted forms:
 * <ul>
 *   <li>Plain FQDN: {@code example.com}, {@code app.example.pro}</li>
 *   <li>Wildcard: {@code *.example.com}, {@code *.app.example.pro}</li>
 * </ul>
 *
 * <p>Rejected:
 * <ul>
 *   <li>Double wildcards ({@code *.*.example.com})</li>
 *   <li>Infix wildcards ({@code foo*.example.com})</li>
 *   <li>Single-label names without a TLD ({@code localhost})</li>
 * </ul>
 *
 * <p>{@code null} and blank values pass (pair with {@code @NotBlank} if required).
 * Designed for use as a container-element constraint on {@code List<String>}:
 * <pre>{@code
 *   private List<@ValidSanPattern String> patterns;
 * }</pre>
 */
@Documented
@Constraint(validatedBy = SanPatternValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidSanPattern {

    String message() default
            "must be a valid domain (e.g. example.com) or wildcard pattern (e.g. *.example.com)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
