// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.messaging.transport.InboundSenders;
import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.PostgresMessageQueue;
import com.certmanagement.messaging.transport.QueueInboundSenders;
import com.certmanagement.messaging.transport.TransportProperties;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The message transport: PostgreSQL is the message queue.
 *
 * <p>Commands for agents, agent results and notifications all go through the
 * {@code message_queue} table. Agents and the notifier reach it through the HTTPS agent gateway,
 * so a self-hosted install needs nothing beyond the database it already has.
 */
@Slf4j
@Configuration
public class PostgresTransportConfig {

    @Bean
    public PostgresMessageQueue postgresMessageQueue(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
                                                     TransportProperties properties) {
        log.info("Message transport: PostgreSQL queue (agents connect through /api/v1/agent-gateway)");
        return new PostgresMessageQueue(jdbcTemplate, objectMapper, properties);
    }

    @Bean
    public InboundSenders queueInboundSenders(PostgresMessageQueue queue) {
        return new QueueInboundSenders(queue);
    }

    @Bean("certNotificationsSender")
    public MessageSender certNotificationsSender(PostgresMessageQueue queue, TransportProperties properties) {
        String channel = properties.getNotificationsChannel();
        return message -> queue.send(channel, message);
    }
}
