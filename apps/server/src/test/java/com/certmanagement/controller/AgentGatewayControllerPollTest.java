// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.messaging.transport.AgentGatewayLimits;
import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.messaging.transport.PostgresMessageQueue;
import com.certmanagement.messaging.transport.PostgresMessageQueue.ReceivedMessage;
import com.certmanagement.messaging.transport.TransportProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The gateway's long poll: adaptive pauses on a fake clock, the max it returns, and what each call counts. */
class AgentGatewayControllerPollTest {

    private static final String INTERNAL = "Bearer internal-secret";

    private final PostgresMessageQueue queue = mock(PostgresMessageQueue.class);
    private final AgentTokenService tokens = mock(AgentTokenService.class);
    private final TransportProperties properties = new TransportProperties();
    private final AtomicLong now = new AtomicLong(1_000_000_000L);
    private final List<Long> pauses = new ArrayList<>();

    @BeforeEach
    void setUp() {
        properties.setInternalToken("internal-secret");
        properties.setMaxReceiveWait(Duration.ofSeconds(25));
    }

    private AgentGatewayController controller(AgentGatewayLimits limits) {
        AgentGatewayController controller = new AgentGatewayController(queue, tokens, properties, limits);
        controller.useClock(now::get, millis -> {
            pauses.add(millis);
            now.addAndGet(Duration.ofMillis(millis).toNanos());
        });
        return controller;
    }

    private static ReceivedMessage message(long id) {
        return new ReceivedMessage(id, UUID.randomUUID(), "notifications", null, "{}", Map.of(), 0,
                OffsetDateTime.now(), OffsetDateTime.now().plusMinutes(2));
    }

    @Test
    void anIdlePollBacksOffFrom250msTo2sAndStillWaitsTheFullTime() throws Exception {
        when(queue.receive(anyString(), anyInt(), any())).thenReturn(List.of());

        assertThat(controller(null).receive(INTERNAL, null, 1, 20)).isEmpty();

        assertThat(pauses.subList(0, 5)).containsExactly(250L, 500L, 1000L, 2000L, 2000L);
        assertThat(pauses).allMatch(p -> p <= 2000L);
        assertThat(pauses.stream().mapToLong(Long::longValue).sum()).isEqualTo(20_000L);
    }

    @Test
    void aFoundMessageEndsThePollAndTheNextPollStartsShortAgain() throws Exception {
        when(queue.receive(anyString(), anyInt(), any())).thenReturn(List.of(), List.of(), List.of(message(1)), List.of());
        AgentGatewayController controller = controller(null);

        assertThat(controller.receive(INTERNAL, null, 1, 20)).hasSize(1);
        assertThat(pauses).containsExactly(250L, 500L);

        pauses.clear();
        controller.receive(INTERNAL, null, 1, 1);
        assertThat(pauses.get(0)).isEqualTo(250L);
    }

    @Test
    void theGatewayNeverReturnsMoreThanTheRequestedMax() throws Exception {
        when(queue.receive(anyString(), anyInt(), any())).thenReturn(List.of(message(1), message(2), message(3)));

        assertThat(controller(null).receive(INTERNAL, null, 1, 0)).hasSize(1);
    }

    @Test
    void onlyReceivesCountAgainstThePollLimitAndSettlesAgainstTheirOwn() throws Exception {
        AgentGatewayLimits limits = mock(AgentGatewayLimits.class);
        when(tokens.identify("cpa_agent")).thenReturn(Optional.of(
                new com.certmanagement.messaging.transport.AgentTokenService.Identity(9L, 5L)));
        when(queue.receive(anyString(), anyInt(), any())).thenReturn(List.of(message(1)));
        when(queue.complete(anyString(), eq(1L), org.mockito.ArgumentMatchers.any())).thenReturn(true);
        AgentGatewayController controller = controller(limits);
        String key = AgentGatewayLimits.keyOf("cpa_agent");

        controller.receive("Bearer cpa_agent", null, 1, 0);
        verify(limits).countRequest(key, AgentGatewayLimits.RequestKind.POLL);
        verify(limits, never()).countRequest(key, AgentGatewayLimits.RequestKind.SETTLE);

        controller.complete("Bearer cpa_agent", 1L, null,
                new AgentGatewayController.SettleRequest(UUID.randomUUID(), null, null));
        verify(limits).countRequest(key, AgentGatewayLimits.RequestKind.SETTLE);
    }
}
