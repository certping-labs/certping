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
 * Validates that a string is an absolute {@code https://} URL with a host, so it is safe to render
 * as a link or image source in a customer's browser ({@code javascript:}, {@code data:} and
 * plain {@code http:} are rejected). {@code null} and blank values pass.
 */
@Documented
@Constraint(validatedBy = HttpsUrlValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface HttpsUrl {

    String message() default "must be an https:// URL";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
