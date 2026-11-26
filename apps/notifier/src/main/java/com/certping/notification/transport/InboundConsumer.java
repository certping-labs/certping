// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

/** Delivers notification messages to the listener until stopped. */
public interface InboundConsumer {

    void start();

    void stop();

    void close();

    boolean isRunning();
}
