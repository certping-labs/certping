// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * The enforced deadline for one send to one recipient, based on the provider's timeouts. A
 * deliver-once claim must outlast it: were a send still under way when its claim lapsed, a second
 * consumer could claim the recipient and send too. The application refuses to start otherwise.
 *
 * <p>An event sends to its recipients one after another for at most one claim lease, starting no
 * send that could not finish inside it; the recipients it did not reach are retried.
 */
@Component
class DeliveryTimeouts {

    /** Time beyond the event budget for the database work around the sends. */
    private static final Duration EVENT_MARGIN = Duration.ofSeconds(30);

    private final Duration sendBudget;
    private final Duration eventBudget;

    DeliveryTimeouts(@Value("${email.provider:smtp}") String provider,
                     @Value("${spring.mail.properties.mail.smtp.connectiontimeout:30000}") long smtpConnectMillis,
                     @Value("${spring.mail.properties.mail.smtp.writetimeout:30000}") long smtpWriteMillis,
                     @Value("${spring.mail.properties.mail.smtp.timeout:30000}") long smtpReadMillis,
                     @Value("${notifier.delivery.acs-timeout:PT30S}") Duration acsTimeout,
                     @Value("${notifier.delivery.claim-lease:PT5M}") Duration lease) {
        this.eventBudget = lease;
        this.sendBudget = "acs".equals(provider)
                ? acsTimeout.multipliedBy(4)
                : Duration.ofMillis(smtpConnectMillis + smtpWriteMillis + smtpReadMillis);
        if (sendBudget.isZero() || sendBudget.isNegative() || sendBudget.compareTo(lease) >= 0) {
            throw new IllegalStateException("a send may take " + sendBudget + ", which the deliver-once claim of "
                    + lease + " does not outlast; shorten the provider timeouts or lengthen notifier.delivery.claim-lease");
        }
    }

    Duration sendBudget() {
        return sendBudget;
    }

    /** Whether an event that has been sending for {@code elapsed} may start another send. */
    boolean canStartSend(Duration elapsed) {
        return elapsed.plus(sendBudget).compareTo(eventBudget) <= 0;
    }

    /** How long one event may take, its sends and their bookkeeping together. */
    Duration eventDeadline() {
        return eventBudget.plus(EVENT_MARGIN);
    }

    /** Whether a send starting {@code elapsed} after its claim still ends before the claim lapses. */
    boolean fitsInLease(Duration lease, Duration elapsed) {
        return elapsed.plus(sendBudget).compareTo(lease) < 0;
    }
}
