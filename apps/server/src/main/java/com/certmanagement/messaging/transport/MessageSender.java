// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

/**
 * Sends one message to one channel of the PostgreSQL message queue.
 */
public interface MessageSender {

    void sendMessage(TransportMessage message);
}
