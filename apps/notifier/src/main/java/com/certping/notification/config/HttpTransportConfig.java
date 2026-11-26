// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import com.certping.notification.service.NotificationMessageHandler;
import com.certping.notification.transport.GatewayClient;
import com.certping.notification.transport.HttpInboundConsumer;
import com.certping.notification.transport.HttpMessageSender;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.MessageSender;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;

/**
 * The notifier's only transport: it reads the server's notifications channel over HTTPS, with
 * the internal token.
 *
 * <p>One channel carries every notification. The {@code notificationType} property picks the
 * handler here.
 */
@Slf4j
@Configuration
public class HttpTransportConfig {

    static final String SYSTEM_EVENT = "SYSTEM_EVENT";

    @Bean
    public GatewayClient notifierGatewayClient(
            @Value("${notifier.transport.server-url:${CERTPING_SERVER_URL:}}") String serverUrl,
            @Value("${notifier.transport.token:${CERTPING_INTERNAL_TOKEN:}}") String token,
            @Value("${notifier.transport.request-timeout:PT30S}") Duration requestTimeout,
            ObjectMapper objectMapper) {
        return new GatewayClient(serverUrl, token, requestTimeout, objectMapper);
    }

    @Bean
    public MessageSender notificationsSender(GatewayClient notifierGatewayClient) {
        return new HttpMessageSender(notifierGatewayClient, "notifications");
    }

    @Bean
    public NotificationConsumers notificationConsumers(
            GatewayClient notifierGatewayClient, NotificationMessageHandler messageHandler,
            @Value("${notifier.transport.concurrency:4}") int concurrency,
            @Value("${notifier.transport.poll-wait:PT20S}") Duration pollWait,
            @Value("${notifier.transport.max-lock-renewal:PT24H}") Duration maxLockRenewal) {
        HttpInboundConsumer consumer = new HttpInboundConsumer(notifierGatewayClient,
                router(messageHandler::processSystemEvent, messageHandler::processAccountEvent),
                concurrency, pollWait, maxLockRenewal);
        consumer.start();
        log.info("Notifier reading the notifications channel through the agent gateway (concurrency={})", concurrency);
        return new NotificationConsumers(List.of(consumer));
    }

    /** Routes SYSTEM_EVENT messages to one handler and the rest to the other. */
    static Consumer<InboundContext> router(Consumer<InboundContext> systemEvents,
                                           Consumer<InboundContext> accountEvents) {
        return context -> {
            Object type = context.getMessage().getApplicationProperties().get("notificationType");
            if (type != null && SYSTEM_EVENT.equals(type.toString())) {
                systemEvents.accept(context);
            } else {
                accountEvents.accept(context);
            }
        };
    }
}
