// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import com.certping.notification.transport.InboundConsumer;

import java.util.List;

/** The notifications channel consumers; Spring closes them when the context shuts down. */
public record NotificationConsumers(List<InboundConsumer> processors) implements AutoCloseable {

    public NotificationConsumers {
        processors = List.copyOf(processors);
    }

    public boolean allRunning() {
        return !processors.isEmpty() && processors.stream().allMatch(InboundConsumer::isRunning);
    }

    @Override
    public void close() {
        RuntimeException failure = null;
        for (InboundConsumer processor : processors) {
            try {
                processor.close();
            } catch (RuntimeException e) {
                if (failure == null) {
                    failure = e;
                } else {
                    failure.addSuppressed(e);
                }
            }
        }
        if (failure != null) {
            throw failure;
        }
    }
}
