// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.transport;

/**
 * A received message plus the operations that settle it.
 */
public interface InboundContext {

    InboundMessage getMessage();

    /** Name of the queue the message came from, for logs. */
    String getEntityPath();

    void complete();

    void abandon();

    void deadLetter(DeadLetterOptions options);
}
