// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CronRun;
import com.certmanagement.repository.CronRunRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * On pod boot, opportunistically joins any drain that is currently RUNNING
 * (active_pod_count &gt; 0 within TTL) so HPA-scaled-up pods can help complete
 * in-flight work rather than sitting idle until the next scheduled fire.
 * Work is submitted after {@link ApplicationReadyEvent} so drain latency cannot
 * delay the application from becoming ready to serve HTTP requests.
 *
 * <p>Stale counters (activity older than STALE_AFTER — assumed to come from a
 * hard-crashed pod that couldn't decrement) are reset via a race-safe conditional
 * UPDATE rather than joined.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SchedulerStartupJoiner {

    static final Duration STALE_AFTER = Duration.ofMinutes(10);

    private final CronRunRepository repo;
    private final DrainRunner drainRunner;
    private final TaskScheduler taskScheduler;
    private final SchedulerExecutionPolicy executionPolicy;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        try {
            taskScheduler.schedule(this::runJoinerWork, Instant.now());
        } catch (TaskRejectedException e) {
            log.error("[Joiner] Could not submit startup join work", e);
        }
    }

    private void runJoinerWork() {
        String joinerId = UUID.randomUUID().toString();
        String parentReq = MDC.get("requestId");
        String parentCorr = MDC.get("correlationId");
        MDC.put("requestId", "req-joiner-" + joinerId);
        MDC.put("correlationId", "corr-joiner-" + joinerId);
        try {
            runInner();
        } finally {
            restore("requestId", parentReq);
            restore("correlationId", parentCorr);
        }
    }

    private static void restore(String key, String value) {
        if (value != null) MDC.put(key, value);
        else MDC.remove(key);
    }

    private void runInner() {
        OffsetDateTime staleCutoff = OffsetDateTime.now(ZoneOffset.UTC).minus(STALE_AFTER);
        for (CronRun r : repo.findAll()) {
            if (r.getActivePodCount() <= 0) {
                continue;
            }
            if (r.getLastActivityAt().isBefore(staleCutoff)) {
                int reset = repo.resetIfStale(r.getCronName(), staleCutoff);
                if (reset > 0) {
                    log.warn("[Joiner] Reset stale active_pod_count for {} (was {})",
                            r.getCronName(), r.getActivePodCount());
                }
                continue;
            }
            if (!executionPolicy.canRun(r.getCronName())) {
                continue;
            }
            log.info("[Joiner] Joining in-progress drain (activePods={}): {}",
                    r.getActivePodCount(), r.getCronName());
            try {
                drainRunner.runDrain(r.getCronName());
            } catch (Exception e) {
                log.error("[Joiner] Drain failed while joining {}: {}",
                        r.getCronName(), e.getMessage(), e);
            }
        }
    }
}
