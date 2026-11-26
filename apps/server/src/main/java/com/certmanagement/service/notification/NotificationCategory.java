// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.notification;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The informational notifications an organization's admins may turn off, by category. This is an
 * allow-list: an action named here can be turned off, and every other action, including one added
 * later, is always sent. Security and account, failure, expiry and action-needed, and
 * service-change notices are never listed.
 *
 * <p>Actions are the notifier's {@code NotificationAction} names, the strings the server sends. None is an incident action of
 * {@code IntegrationNotificationClient}, so PagerDuty and ServiceNow never depend on a preference.
 */
public enum NotificationCategory {

    /** Certificate issued, renewed or deployed. */
    CERTIFICATE_ACTIVITY(Set.of("CERT_ISSUANCE_SUCCESS", "CERT_RENEWAL_SUCCESS", "CERT_DEPLOYMENT_SUCCESS")),

    /** Activity digests; their details stay in the app. */
    REPORTS(Set.of("IOT_ACTIVITY_DIGEST"));

    private static final Map<String, NotificationCategory> BY_ACTION = Arrays.stream(values())
            .flatMap(category -> category.actions.stream().map(action -> Map.entry(action, category)))
            .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));

    private static final Map<String, NotificationCategory> BY_NAME = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(Enum::name, Function.identity()));

    private final Set<String> actions;

    NotificationCategory(Set<String> actions) {
        this.actions = actions;
    }

    /** The actions of this category. */
    public Set<String> actions() {
        return actions;
    }

    /** The category {@code action} belongs to; empty for an action that is always sent. */
    public static Optional<NotificationCategory> of(String action) {
        return action == null ? Optional.empty() : Optional.ofNullable(BY_ACTION.get(action));
    }

    /** The category named {@code name}; empty for a name that is not one. */
    public static Optional<NotificationCategory> named(String name) {
        return name == null ? Optional.empty() : Optional.ofNullable(BY_NAME.get(name));
    }
}
