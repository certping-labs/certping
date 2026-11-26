// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.constants.Paths;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What an audit export may hold while it streams: no open-in-view connection for the whole download, and a
 * thread of a small bounded MVC async pool of its own, not the shared applicationTaskExecutor.
 */
class AuditExportResourcesTest {

    @Test
    void everyExportRouteRunsOutsideOpenInView() {
        assertThat(WebConfig.OUTSIDE_OPEN_IN_VIEW).contains(Paths.AUDIT_LOGS_EXPORT, Paths.AUDIT_LOGS_ACCESS_EXPORT,
                Paths.ADMIN_AUDIT_LOGS_EXPORT);
    }

    @Test
    void mvcAsyncBodiesRunOnABoundedPoolSizedToTheExportsAPodStreams() {
        MvcAsyncConfig config = new MvcAsyncConfig(3);
        AsyncTaskExecutor[] chosen = new AsyncTaskExecutor[1];
        AsyncSupportConfigurer configurer = new AsyncSupportConfigurer() {
            @Override
            public AsyncSupportConfigurer setTaskExecutor(AsyncTaskExecutor taskExecutor) {
                chosen[0] = taskExecutor;
                return super.setTaskExecutor(taskExecutor);
            }
        };

        config.configureAsyncSupport(configurer);

        assertThat(chosen[0]).isInstanceOf(ThreadPoolTaskExecutor.class);
        ThreadPoolTaskExecutor pool = (ThreadPoolTaskExecutor) chosen[0];
        assertThat(pool.getCorePoolSize()).isEqualTo(3);
        assertThat(pool.getMaxPoolSize()).isEqualTo(3);
        assertThat(pool.getQueueCapacity()).isEqualTo(3);
        assertThat(pool.getThreadNamePrefix()).isEqualTo(MvcAsyncConfig.THREAD_PREFIX);
        assertThat(configurer).extracting("callableInterceptors").asList()
                .as("an export's slot is given back when its request completes")
                .hasAtLeastOneElementOfType(com.certmanagement.audit.AuditExportSlotInterceptor.class);
        assertThatThrownBy(() -> new MvcAsyncConfig(0)).isInstanceOf(IllegalArgumentException.class);
    }
}
