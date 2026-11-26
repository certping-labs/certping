// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import com.certping.agent.transport.InboundConsumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Starts and stops the inbound gateway consumer, and is the one source of truth for whether the
 * agent is listening (used by health and the heartbeat).
 */
@Slf4j
@Component
public class InboundConsumerLifecycle {

    private final String source;
    private final InboundConsumer consumer;

    public InboundConsumerLifecycle(AgentProperties properties, InboundConsumer inboundConsumer) {
        this.source = "agent-gateway " + properties.getTransport().getServerUrl();
        this.consumer = inboundConsumer;
    }

    /**
     * Defers listener startup until the application is ready, which avoids receiving messages before downstream
     * collaborators such as senders, processors, and health publishers are fully initialized.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void startConsumer() {
        log.info("Starting inbound consumer: {}", describe());
        try {
            consumer.start();
            log.info("Inbound consumer started");
        } catch (RuntimeException e) {
            log.error("Failed to start inbound consumer: {}", e.getMessage(), e);
            throw new IllegalStateException("Failed to start inbound consumer for " + source, e);
        }
    }

    /**
     * Stops polling on context shutdown so the server stops handing us new work before the JVM tears down the
     * beans that finish, log, or report the current message.
     */
    @EventListener(ContextClosedEvent.class)
    public void stopConsumer() {
        log.info("Stopping inbound consumer");
        try {
            stopAndClose();
            log.info("Inbound consumer stopped");
        } catch (RuntimeException e) {
            log.warn("Inbound consumer shutdown encountered an error: {}", e.getMessage(), e);
        }
    }

    void stopAndClose() {
        RuntimeException firstFailure = null;
        try {
            consumer.stop();
        } catch (RuntimeException e) {
            firstFailure = new IllegalStateException("Failed to stop inbound consumer for " + source, e);
        } finally {
            try {
                consumer.close();
            } catch (RuntimeException e) {
                if (firstFailure == null) {
                    firstFailure = new IllegalStateException("Failed to close inbound consumer for " + source, e);
                } else {
                    firstFailure.addSuppressed(e);
                }
            }
        }
        if (firstFailure != null) {
            throw firstFailure;
        }
    }

    public boolean isRunning() {
        return consumer.isRunning();
    }

    public Map<String, String> states() {
        return Map.of("inboundConsumer", consumer.isRunning() ? "RUNNING" : "STOPPED");
    }

    public String describe() {
        return "inbound=" + source;
    }
}
