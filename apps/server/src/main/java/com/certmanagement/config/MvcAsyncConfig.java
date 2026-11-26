// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.audit.AuditExportSlotInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * The executor Spring MVC runs async request bodies on: today only the audit exports
 * ({@code StreamingResponseBody}). A small bounded pool of its own, so a burst of exports cannot take the
 * shared {@code applicationTaskExecutor} (every {@code @Async} method's) nor grow without bound. Sized to the
 * exports a pod streams at once ({@code certping.audit.export-concurrency}, which
 * {@link com.certmanagement.audit.AuditTrailExporter} enforces before an export starts), with as many queued.
 *
 * <p>{@link AuditExportSlotInterceptor} gives an export's slot back when its request completes, also when the body
 * was rejected by this pool or the request timed out before it ran.
 *
 * <p>Unordered, so it runs after Spring Boot's own MVC configurer ({@code @Order(0)}), whose executor this
 * replaces; the request timeout stays Boot's ({@code spring.mvc.async.request-timeout}).
 */
@Configuration
public class MvcAsyncConfig implements WebMvcConfigurer {

    static final String THREAD_PREFIX = "mvc-async-";

    private final int concurrency;

    public MvcAsyncConfig(@Value("${certping.audit.export-concurrency:4}") int concurrency) {
        if (concurrency < 1) {
            throw new IllegalArgumentException("certping.audit.export-concurrency must be positive, was " + concurrency);
        }
        this.concurrency = concurrency;
    }

    @Bean
    public ThreadPoolTaskExecutor mvcAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(concurrency);
        executor.setMaxPoolSize(concurrency);
        executor.setQueueCapacity(concurrency);
        executor.setThreadNamePrefix(THREAD_PREFIX);
        // A pod shutting down lets the exports in flight finish within the shutdown phase.
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(20);
        return executor;
    }

    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        configurer.setTaskExecutor(mvcAsyncExecutor());
        // An export's slot is given back when its request completes, even if its body never ran.
        configurer.registerCallableInterceptors(new AuditExportSlotInterceptor());
    }
}
