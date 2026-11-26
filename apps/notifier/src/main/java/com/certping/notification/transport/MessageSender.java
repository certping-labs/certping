// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

/**
 * Sends a message to the notifications channel. {@link TransportMessage} carries the body, message
 * id, properties, schedule and time to live.
 */
public interface MessageSender {

    void sendMessage(TransportMessage message);

    /** Name of the destination, for logs. */
    String getEntityPath();
}
