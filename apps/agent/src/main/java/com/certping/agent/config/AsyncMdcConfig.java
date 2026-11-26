// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import com.certping.agent.util.MdcContextPropagator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Wires MDC propagation into every Spring-managed executor.
 *
 * <p>Without this, anything that uses {@code @Async} or any
 * {@link org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor} bean would run with an
 * empty MDC on the worker thread — losing the {@code [req= corr= msg= org=]} prefix on every
 * log line emitted inside the async call.
 *
 * <p>The {@link TaskDecorator} bean is auto-applied to Spring Boot's auto-configured task
 * executor builder, which in turn is what {@code @EnableAsync} uses to build its default executor.
 * Custom {@code ThreadPoolTaskExecutor} beans should call {@code setTaskDecorator(mdcTaskDecorator)}
 * explicitly to opt in.
 *
 * <p>The decorator delegates to {@link MdcContextPropagator#wrap(Runnable)} so the behaviour
 * matches the manual wrapping done at ad-hoc concurrent call sites.
 */
@Configuration
@EnableAsync
public class AsyncMdcConfig {

    @Bean
    public TaskDecorator mdcTaskDecorator() {
        return MdcContextPropagator::wrap;
    }
}
