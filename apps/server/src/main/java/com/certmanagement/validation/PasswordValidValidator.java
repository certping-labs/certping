// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.service.PasswordPolicy;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Adapts {@link PasswordPolicy} to the Bean Validation API.
 *
 * <p>Stateless and safe to inject as a Spring bean — Hibernate Validator picks up
 * Spring-managed validators automatically.</p>
 */
@Component
@RequiredArgsConstructor
public class PasswordValidValidator implements ConstraintValidator<PasswordValid, String> {

    private final PasswordPolicy policy;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return true; // let @NotBlank handle nulls separately
        try {
            // Context-free check: no username/email comparison at this layer.
            policy.validate(password, null, null);
            return true;
        } catch (BadRequestException e) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(e.getMessage()).addConstraintViolation();
            return false;
        }
    }
}
