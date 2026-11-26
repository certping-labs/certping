// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.transport;

/**
 * Sends a message to the CertPing server.
 */
public interface MessageSender {

    void sendMessage(TransportMessage message);

    /** Name of the destination, for logs. */
    String getEntityPath();
}
