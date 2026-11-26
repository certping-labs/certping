// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

/** {@link InboundSenders} over the built-in queue: the queue name is the channel. */
public record QueueInboundSenders(PostgresMessageQueue queue) implements InboundSenders {

    @Override
    public MessageSender senderFor(String queueName) {
        return message -> queue.send(queueName, message);
    }
}
