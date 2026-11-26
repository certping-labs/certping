// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import com.certping.notification.service.NotificationMessageHandler;
import com.certping.notification.transport.GatewayClient;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.InboundMessage;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HttpTransportConfigTest {

    private static InboundContext contextWith(Map<String, Object> properties) {
        InboundMessage message = mock(InboundMessage.class);
        when(message.getApplicationProperties()).thenReturn(properties);
        InboundContext context = mock(InboundContext.class);
        when(context.getMessage()).thenReturn(message);
        return context;
    }

    @Test
    void routesByNotificationType() {
        java.util.List<InboundContext> systemSeen = new java.util.ArrayList<>();
        java.util.List<InboundContext> accountSeen = new java.util.ArrayList<>();
        InboundContext system = contextWith(Map.of("notificationType", "SYSTEM_EVENT"));
        InboundContext account = contextWith(Map.of("notificationType", "ACCOUNT_EVENT"));
        InboundContext untyped = contextWith(Map.of());

        var router = HttpTransportConfig.router(systemSeen::add, accountSeen::add);
        router.accept(system);
        router.accept(account);
        router.accept(untyped);

        assertThat(systemSeen).containsExactly(system);
        assertThat(accountSeen).containsExactly(account, untyped);
    }

    @Test
    void buildsTheHttpBeans() {
        HttpTransportConfig config = new HttpTransportConfig();
        GatewayClient client = config.notifierGatewayClient("https://certping.example.com", "internal",
                Duration.ofSeconds(5), JsonMapper.builderWithJackson2Defaults().build());
        assertThat(config.notificationsSender(client).getEntityPath()).isEqualTo("agent-gateway/notifications");

        NotificationConsumers consumers = config.notificationConsumers(client, new NotificationMessageHandler(null, null, null, null, null, null),
                1, Duration.ZERO, Duration.ofMinutes(1));
        try (consumers) {
            assertThat(consumers.allRunning()).isTrue();
        }
        assertThat(consumers.allRunning()).isFalse();

        assertThatThrownBy(() -> config.notifierGatewayClient("", "t", Duration.ofSeconds(1), JsonMapper.builderWithJackson2Defaults().build()))
                .hasMessageContaining("CERTPING_SERVER_URL");
    }
}
