// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import org.junit.jupiter.api.Test;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import static org.assertj.core.api.Assertions.assertThat;

class SchedulerConfigTest {

    @Test
    void taskScheduler_hasExpectedPoolSizeAndPrefix() {
        TaskScheduler scheduler = new SchedulerConfig().taskScheduler();

        assertThat(scheduler).isInstanceOf(ThreadPoolTaskScheduler.class);
        ThreadPoolTaskScheduler pool = (ThreadPoolTaskScheduler) scheduler;
        assertThat(pool.getScheduledThreadPoolExecutor().getCorePoolSize()).isEqualTo(10);
        assertThat(pool.getThreadNamePrefix()).isEqualTo("cron-");
    }
}
