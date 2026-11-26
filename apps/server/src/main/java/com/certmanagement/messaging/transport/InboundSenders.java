// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

/**
 * Senders for agents' inbound queues ({@code {orgId}-agent-inbound}), keyed by queue name.
 * Implemented over the PostgreSQL queue by {@link QueueInboundSenders}.
 */
public interface InboundSenders {

    MessageSender senderFor(String queueName);
}
