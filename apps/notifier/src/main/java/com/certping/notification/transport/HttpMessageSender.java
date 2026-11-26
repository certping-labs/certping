// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

/**
 * Sends through the agent gateway to the notifications channel (retries and replays).
 */
public class HttpMessageSender implements MessageSender {

    private final GatewayClient client;
    private final String queue;

    public HttpMessageSender(GatewayClient client, String queue) {
        this.client = client;
        this.queue = queue;
    }

    @Override
    public void sendMessage(TransportMessage message) {
        client.sendMessage(queue, message.getMessageId(), message.getBody().toString(),
                message.getApplicationProperties(), message.getScheduledEnqueueTime(), message.getTimeToLive());
    }

    @Override
    public String getEntityPath() {
        return "agent-gateway/" + queue;
    }
}
