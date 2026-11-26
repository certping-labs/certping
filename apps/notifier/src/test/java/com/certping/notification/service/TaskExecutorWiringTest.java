// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.task.TaskSchedulingAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.EnableScheduling;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Scheduling adds a taskScheduler, which is a TaskExecutor too; the listener must still get the
 * notification executor, or the application does not start.
 */
class TaskExecutorWiringTest {

    @Configuration
    @EnableScheduling
    static class Scheduling {
        @Bean
        TaskExecutor notificationTaskExecutor() {
            return new SyncTaskExecutor();
        }

        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }

    @Test
    void theListenerGetsTheNotificationExecutorBesideTheScheduler() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TaskSchedulingAutoConfiguration.class))
                .withUserConfiguration(Scheduling.class)
                .withBean(NotificationService.class, () -> mock(NotificationService.class))
                .withBean(ScheduledRetryService.class, () -> mock(ScheduledRetryService.class))
                .withBean(UndeliveredEmailService.class, () -> mock(UndeliveredEmailService.class))
                .withBean(DeliveryTimeouts.class, () -> mock(DeliveryTimeouts.class))
                .withBean(NotificationMessageHandler.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("taskScheduler");
                    assertThat(context).hasSingleBean(NotificationMessageHandler.class);
                });
    }
}
