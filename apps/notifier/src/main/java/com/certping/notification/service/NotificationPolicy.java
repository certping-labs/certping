// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.model.NotificationEvent;

import java.util.Optional;

/** Whether an organization's notification may be delivered, by the notification settings its admins chose. */
public interface NotificationPolicy {

    /**
     * The category the organization turned off for this event, or empty to deliver it. Never throws:
     * when the answer cannot be had, the event is delivered.
     */
    Optional<String> suppressedCategory(NotificationEvent event);
}
