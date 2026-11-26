// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * A notification message received from the server. {@link #getDeliveryCount()} is 0 on the
 * first delivery.
 */
public interface InboundMessage {

    MessageBody getBody();

    Map<String, Object> getApplicationProperties();

    String getMessageId();

    long getDeliveryCount();

    OffsetDateTime getEnqueuedTime();

    long getSequenceNumber();

    default String getCorrelationId() {
        return null;
    }

    default String getSubject() {
        return null;
    }
}
