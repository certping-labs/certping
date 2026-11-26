// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Checks every component once per {@link PublicStatusBoard#CHECK_INTERVAL}, so the public endpoint
 * costs the dependencies the same whatever its traffic. The checks of a round run in parallel
 * and share one deadline; a check still running at the deadline is interrupted and counts as failed.
 * Starting runs the first round before returning, so a new pod reports ready only with a document.
 */
@Slf4j
@Component
public class PublicStatusRefresher implements SmartLifecycle {

    static final String HEALTH_GROUP_PATH = "/actuator/health/status";
    static final Duration CHECK_DEADLINE = Duration.ofSeconds(2);

    private final PublicStatusBoard board;
    private final DatabaseCheck database;
    private final HealthGroupProbe probe;
    private final URI notifierGroup;
    private final URI agentGroup;
    private final Duration deadline;
    private final ExecutorService checks;
    private final Map<PublicComponent, Future<Boolean>> lastChecks = new EnumMap<>(PublicComponent.class);
    private final Map<PublicComponent, AtomicBoolean> running = new EnumMap<>(PublicComponent.class);
    private ScheduledExecutorService schedule;

    @Autowired
    public PublicStatusRefresher(PublicStatusBoard board, DatabaseCheck database, HealthGroupProbe probe,
                                 @Value("${notification-service.base-url}") String notifierBaseUrl,
                                 @Value("${public-status.agent-base-url}") String agentBaseUrl) {
        this(board, database, probe, notifierBaseUrl, agentBaseUrl, CHECK_DEADLINE,
                // One thread per component: a round never waits for a free thread.
                Executors.newFixedThreadPool(PublicComponent.values().length, daemon("public-status-check")));
    }

    PublicStatusRefresher(PublicStatusBoard board, DatabaseCheck database, HealthGroupProbe probe,
                          String notifierBaseUrl, String agentBaseUrl,
                          Duration deadline, ExecutorService checks) {
        this.board = board;
        this.database = database;
        this.probe = probe;
        this.notifierGroup = healthGroup("notification-service.base-url", notifierBaseUrl);
        this.agentGroup = healthGroup("public-status.agent-base-url", agentBaseUrl);
        this.deadline = deadline;
        this.checks = checks;
        for (PublicComponent component : PublicComponent.values()) {
            running.put(component, new AtomicBoolean());
        }
    }

    @Override
    public synchronized void start() {
        if (schedule != null) {
            return;
        }
        refresh();
        schedule = Executors.newSingleThreadScheduledExecutor(daemon("public-status"));
        long interval = PublicStatusBoard.CHECK_INTERVAL.toMillis();
        schedule.scheduleWithFixedDelay(this::refresh, interval, interval, TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void stop() {
        if (schedule != null) {
            schedule.shutdownNow();
            schedule = null;
        }
    }

    @Override
    public synchronized boolean isRunning() {
        return schedule != null;
    }

    @PreDestroy
    void shutdown() {
        stop();
        checks.shutdownNow();
    }

    public synchronized void refresh() {
        Map<PublicComponent, Future<Boolean>> round = new EnumMap<>(PublicComponent.class);
        round.put(PublicComponent.API, launch(PublicComponent.API, database::answers));
        if (board.reports(PublicComponent.NOTIFICATIONS)) {
            // Without a mail server the page leaves email notifications out, so the notifier is not asked.
            round.put(PublicComponent.NOTIFICATIONS,
                    launch(PublicComponent.NOTIFICATIONS, () -> probe.isUp(notifierGroup)));
        }
        round.put(PublicComponent.CERTIFICATES, launch(PublicComponent.CERTIFICATES, () -> probe.isUp(agentGroup)));
        long deadlineNanos = System.nanoTime() + deadline.toNanos();
        round.forEach((component, check) -> board.record(component, outcome(component, check, deadlineNanos)));
    }

    /**
     * Null while the last check of this component is still queued or running, so a stuck call fails
     * the round instead of piling up threads. A cancelled future reports done even while its thread
     * still runs a call that ignored the interrupt, so the task also flags itself while it runs.
     */
    private Future<Boolean> launch(PublicComponent component, Callable<Boolean> check) {
        Future<Boolean> last = lastChecks.get(component);
        AtomicBoolean active = running.get(component);
        if ((last != null && !last.isDone()) || active.get()) {
            return null;
        }
        try {
            Future<Boolean> next = checks.submit(() -> {
                active.set(true);
                try {
                    return check.call();
                } finally {
                    active.set(false);
                }
            });
            lastChecks.put(component, next);
            return next;
        } catch (RejectedExecutionException e) {
            return null;
        }
    }

    private static boolean outcome(PublicComponent component, Future<Boolean> check, long deadlineNanos) {
        if (check == null) {
            log.warn("Public status check of {} failed: previous check still running", component.id());
            return false;
        }
        try {
            boolean up = check.get(Math.max(0, deadlineNanos - System.nanoTime()), TimeUnit.NANOSECONDS);
            if (!up) {
                log.warn("Public status check of {} failed: not up", component.id());
            }
            return up;
        } catch (TimeoutException e) {
            check.cancel(true);
            log.warn("Public status check of {} failed: timeout", component.id());
            return false;
        } catch (ExecutionException e) {
            log.warn("Public status check of {} failed: error {}", component.id(),
                    e.getCause().getClass().getSimpleName());
            return false;
        } catch (CancellationException e) {
            log.warn("Public status check of {} failed: cancelled", component.id());
            return false;
        } catch (InterruptedException e) {
            check.cancel(true);
            Thread.currentThread().interrupt();
            log.warn("Public status check of {} failed: interrupted", component.id());
            return false;
        }
    }

    private static ThreadFactory daemon(String name) {
        return runnable -> {
            Thread thread = new Thread(runnable, name);
            thread.setDaemon(true);
            return thread;
        };
    }

    static URI healthGroup(String setting, String baseUrl) {
        URI base;
        try {
            base = URI.create(baseUrl.strip().replaceAll("/+$", ""));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(setting + " is not a valid URL", e);
        }
        if (base.getHost() == null || !("http".equals(base.getScheme()) || "https".equals(base.getScheme()))) {
            throw new IllegalStateException(setting + " must be an absolute http(s) URL");
        }
        return URI.create(base + HEALTH_GROUP_PATH);
    }
}
