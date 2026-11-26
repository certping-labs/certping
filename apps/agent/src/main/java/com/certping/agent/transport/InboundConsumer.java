// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.transport;

/** Delivers inbound commands to the agent's listener until stopped. */
public interface InboundConsumer {

    void start();

    void stop();

    void close();

    boolean isRunning();
}
