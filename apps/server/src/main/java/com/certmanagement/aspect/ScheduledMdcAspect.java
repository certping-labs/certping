// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.aspect;

import com.certmanagement.util.OtelSpanContext;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

/**
 * Mints a {@code requestId} into MDC at the start of every {@code @Scheduled} method invocation
 * so background ticks have a stable, traceable identifier that flows end-to-end through any
 * agent commands they publish.
 *
 * <p>We do <em>not</em> set {@code correlationId} here. {@code correlationId} is frontend-owned
 * by contract — there is no upstream caller for a scheduler tick, so it stays empty for the
 * lifetime of that work. This matches the "non-HTTP → no corr" log convention.
 *
 * <p>The minted id has the form {@code req-sched-<methodName>-<short-uuid>} so two different
 * scheduled jobs running concurrently are visually distinguishable in logs.
 *
 * <p>The MDC is restored to its prior state in a finally block so the scheduler ID does not
 * leak into the next task that runs on the same pooled thread.
 */
@Aspect
@Component
@Slf4j
public class ScheduledMdcAspect {

    @Around("@annotation(org.springframework.scheduling.annotation.Scheduled)")
    public Object seedRequestIdForScheduledTick(ProceedingJoinPoint pjp) throws Throwable {
        Map<String, String> previous = MDC.getCopyOfContextMap();
        String method = pjp.getSignature().getName();
        String requestId = "req-sched-" + method + "-" + UUID.randomUUID().toString().substring(0, 8);
        MDC.put("requestId", requestId);
        OtelSpanContext.enrichScheduledTick(requestId);
        try {
            return pjp.proceed();
        } finally {
            MDC.clear();
            if (previous != null) {
                MDC.setContextMap(previous);
            }
        }
    }
}
