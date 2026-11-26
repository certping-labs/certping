// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.health;

import com.certping.notification.transport.InboundConsumer;
import com.certping.notification.config.NotificationConsumers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.health.contributor.Status;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NotificationConsumerHealthIndicatorTest {

    @Test
    void upWhenEveryProcessorIsRunning() {
        assertThat(statusOf(new NotificationConsumers(List.of(processor(true), processor(true)))))
                .isEqualTo(Status.UP);
    }

    @Test
    void downWhenOneProcessorStopped() {
        assertThat(statusOf(new NotificationConsumers(List.of(processor(true), processor(false)))))
                .isEqualTo(Status.DOWN);
    }

    @Test
    void downWhenNoProcessorWasBuilt() {
        assertThat(statusOf(new NotificationConsumers(List.of()))).isEqualTo(Status.DOWN);
    }

    @Test
    void downWhenNoConsumerExists() {
        assertThat(statusOf(null)).isEqualTo(Status.DOWN);
    }

    @Test
    void downWithoutDetailsWhenTheClientThrows() {
        InboundConsumer broken = mock(InboundConsumer.class);
        when(broken.isRunning()).thenThrow(new IllegalStateException("https://internal-host"));

        var health = indicator(new NotificationConsumers(List.of(broken))).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void consumersCopyTheProcessorList() {
        var processors = new ArrayList<InboundConsumer>(List.of(processor(true)));
        NotificationConsumers consumers = new NotificationConsumers(processors);

        processors.add(processor(false));

        assertThat(consumers.allRunning()).isTrue();
    }

    @Test
    void closingClosesEveryProcessorEvenWhenOneFails() {
        InboundConsumer failing = processor(true);
        InboundConsumer other = processor(true);
        IllegalStateException failure = new IllegalStateException("close failed");
        doThrow(failure).when(failing).close();

        assertThatThrownBy(new NotificationConsumers(List.of(failing, other))::close).isSameAs(failure);

        verify(failing).close();
        verify(other).close();
    }

    private static Status statusOf(NotificationConsumers consumers) {
        return indicator(consumers).health().getStatus();
    }

    @SuppressWarnings("unchecked")
    private static NotificationConsumerHealthIndicator indicator(NotificationConsumers consumers) {
        ObjectProvider<NotificationConsumers> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(consumers);
        return new NotificationConsumerHealthIndicator(provider);
    }

    private static InboundConsumer processor(boolean running) {
        InboundConsumer processor = mock(InboundConsumer.class);
        when(processor.isRunning()).thenReturn(running);
        return processor;
    }
}
