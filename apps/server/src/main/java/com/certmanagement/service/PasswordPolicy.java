// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.exception.BadRequestException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Password strength rules for local accounts (setup, reset, change).
 *
 * Rules:
 *   - 8–100 chars
 *   - ≥1 uppercase
 *   - ≥1 digit
 *   - ≥1 special character
 *   - not substring-equal to username or email local-part (case-insensitive)
 *
 * Two flavors:
 *   - {@link #collect(String, String, String)} returns ALL violations as a list, so callers
 *     can show the user every rule they need to fix at once.
 *   - {@link #validate(String, String, String)} throws on the first failure (first-run setup,
 *     password reset and change, {@code @PasswordValid}).
 */
@Component
public class PasswordPolicy {

    private static final Set<Character> SPECIALS = Set.of(
            '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=',
            '[', ']', '{', '}', ';', ':', '\'', '"', '\\', '|', ',', '.', '<', '>',
            '/', '?', '~', '`');

    /**
     * Returns the list of human-readable rule violations. Empty list = password is strong enough.
     * Caller is responsible for surfacing them (typically via {@code FieldError}s on a
     * {@code MethodArgumentNotValidException}-shaped response).
     */
    public List<String> collect(String password, String username, String email) {
        List<String> violations = new ArrayList<>();

        if (password == null || password.length() < 8) {
            violations.add("Password must be at least 8 characters");
            // Don't short-circuit — keep collecting so the user sees every fix in one shot.
        }
        if (password != null && password.length() > 100) {
            violations.add("Password must be no more than 100 characters");
        }
        if (password != null) {
            boolean hasUpper = false, hasDigit = false, hasSpecial = false;
            for (char c : password.toCharArray()) {
                if (Character.isUpperCase(c)) hasUpper = true;
                else if (Character.isDigit(c)) hasDigit = true;
                else if (SPECIALS.contains(c)) hasSpecial = true;
            }
            if (!hasUpper)   violations.add("Password must contain at least one uppercase letter");
            if (!hasDigit)   violations.add("Password must contain at least one digit");
            if (!hasSpecial) violations.add("Password must contain at least one special character");

            String lower = password.toLowerCase(Locale.ROOT);
            if (username != null && !username.isBlank()
                    && lower.contains(username.toLowerCase(Locale.ROOT))) {
                violations.add("Password must not contain your username");
            }
            if (email != null && !email.isBlank()) {
                int at = email.indexOf('@');
                String local = at > 0 ? email.substring(0, at) : email;
                if (local.length() >= 3 && lower.contains(local.toLowerCase(Locale.ROOT))) {
                    violations.add("Password must not contain your email");
                }
            }
        }
        return violations;
    }

    /**
     * Throws {@link BadRequestException} with the first violation found. Kept for backward
     * compatibility with single-error code paths (reset-password, change-password). New code
     * should prefer {@link #collect} so the user sees every rule at once.
     */
    public void validate(String password, String username, String email) {
        List<String> violations = collect(password, username, email);
        if (!violations.isEmpty()) {
            throw new BadRequestException(violations.get(0));
        }
    }
}
