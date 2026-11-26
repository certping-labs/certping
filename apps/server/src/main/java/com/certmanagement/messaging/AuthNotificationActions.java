// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

/**
 * String constants for the account notification actions {@link AuthNotificationPublisher} publishes.
 *
 * <p>Each value resolves to a Thymeleaf template in the notifier via the convention
 * {@code action.toLowerCase().replace("_", "-") + ".html"}; do not rename without changing the
 * notifier's {@code NotificationAction} enum too.</p>
 *
 * <table>
 *   <caption>Action and template</caption>
 *   <tr><th>Constant</th><th>Template</th></tr>
 *   <tr><td>{@link #RESET_PASSWORD}</td><td>reset-password.html</td></tr>
 *   <tr><td>{@link #PASSWORD_CHANGE_SUCCESS}</td><td>password-change-success.html</td></tr>
 * </table>
 */
public final class AuthNotificationActions {

    private AuthNotificationActions() {}

    /** Password-reset link sent in response to /api/auth/forgot-password. Variables: {@code username}, {@code resetLink}. */
    public static final String RESET_PASSWORD = "RESET_PASSWORD";

    /**
     * Confirmation email sent after a successful password reset OR an authenticated change.
     * Both events use the same template since the content is the same: "your password just changed."
     * Variables: {@code username}.
     */
    public static final String PASSWORD_CHANGE_SUCCESS = "PASSWORD_CHANGE_SUCCESS";
}
