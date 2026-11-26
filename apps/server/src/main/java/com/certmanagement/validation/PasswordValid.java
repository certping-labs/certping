// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Bean-Validation constraint that runs the {@link com.certmanagement.service.PasswordPolicy}
 * rules at the binding boundary. Use on DTO fields that accept a new password.
 *
 * <p><b>Note on context:</b> this annotation can't check the "doesn't contain your username
 * or email" rule because it only sees one field. Callers that need that check should still
 * invoke {@code PasswordPolicy.validate(password, username, email)} explicitly in the service
 * layer. This annotation catches the length / character-class rules at the controller boundary
 * before service logic runs.</p>
 */
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordValidValidator.class)
public @interface PasswordValid {

    String message() default "Password does not meet strength requirements";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
