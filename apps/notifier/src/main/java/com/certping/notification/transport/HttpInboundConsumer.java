// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import com.certping.notification.transport.GatewayClient.Leased;
import com.certping.notification.transport.GatewayClient.LeasedMessage;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Long-polls the agent gateway for notifications and hands each to the listener.
 *
 * <p>Each poller thread handles one message at a time. While the listener works, the lock is
 * renewed in the background up to {@code maxLockRenewal}, so long CA orders are not redelivered
 * to another notifier replica. If the server is unreachable the pollers back off and retry; they
 * never give up.
 */
@Slf4j
public class HttpInboundConsumer implements InboundConsumer {

    private static final Duration MAX_BACKOFF = Duration.ofSeconds(30);
    /** Messages one poller asks for. It handles them one at a time, so it never asks for more. */
    static final int RECEIVE_MAX = 1;

    private final GatewayClient client;
    private final Consumer<InboundContext> listener;
    private final int concurrency;
    private final Duration pollWait;
    private final Duration maxLockRenewal;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final List<Thread> pollers = new ArrayList<>();
    private ScheduledExecutorService renewer;
    private volatile Runnable onConnected = () -> { };

    public HttpInboundConsumer(GatewayClient client, Consumer<InboundContext> listener, int concurrency,
                               Duration pollWait, Duration maxLockRenewal) {
        this.client = client;
        this.listener = listener;
        this.concurrency = Math.max(1, concurrency);
        this.pollWait = pollWait;
        this.maxLockRenewal = maxLockRenewal == null ? Duration.ofMinutes(30) : maxLockRenewal;
    }

    /** Runs after every successful poll; for example to record that the server is reachable. */
    public HttpInboundConsumer onConnected(Runnable hook) {
        this.onConnected = hook == null ? () -> { } : hook;
        return this;
    }

    @Override
    public synchronized void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        // One renewer thread per poller: a renewal throttled with HTTP 429 waits and retries, and
        // must not hold up the renewals of the other pollers' messages.
        AtomicInteger renewerIds = new AtomicInteger();
        renewer = Executors.newScheduledThreadPool(concurrency, r -> {
            Thread t = new Thread(r, "gateway-lock-renewer-" + renewerIds.getAndIncrement());
            t.setDaemon(true);
            return t;
        });
        for (int i = 0; i < concurrency; i++) {
            Thread t = new Thread(this::poll, "gateway-poller-" + i);
            t.setDaemon(true);
            t.start();
            pollers.add(t);
        }
    }

    @Override
    public synchronized void stop() {
        running.set(false);
        pollers.forEach(Thread::interrupt);
        for (Thread t : pollers) {
            try {
                t.join(Duration.ofSeconds(10).toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        pollers.clear();
        if (renewer != null) {
            renewer.shutdownNow();
            renewer = null;
        }
    }

    @Override
    public void close() {
        stop();
    }

    @Override
    public boolean isRunning() {
        return running.get();
    }

    private void poll() {
        Duration backoff = Duration.ofSeconds(1);
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                List<Leased> leased = client.receive(RECEIVE_MAX, pollWait);
                backoff = Duration.ofSeconds(1);
                safely(onConnected);
                handle(leased);
            } catch (GatewayClient.GatewayException e) {
                if (!running.get()) {
                    return;
                }
                if (e.getStatus() == 429) {
                    // Throttled: wait as long as the server asks (capped), without growing the back-off.
                    Duration wait = GatewayClient.retryDelay(e, backoff);
                    log.debug("Agent gateway throttled the poll, retrying in {}s", wait.toSeconds());
                    if (!sleep(wait)) {
                        return;
                    }
                    continue;
                }
                log.warn("Agent gateway receive failed, retrying in {}s: {}", backoff.toSeconds(), e.getMessage());
                if (!sleep(backoff)) {
                    return;
                }
                backoff = backoff.multipliedBy(2).compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : backoff.multipliedBy(2);
            } catch (RuntimeException e) {
                log.error("Agent gateway poller error: {}", e.getMessage(), e);
                if (!sleep(backoff)) {
                    return;
                }
            }
        }
    }

    /**
     * Handles one receive result. Anything beyond {@link #RECEIVE_MAX} is abandoned at once so it
     * goes back to READY for another poller; holding it while this poller works would let its
     * lock expire and the server would redeliver it elsewhere (a duplicate CA order). Lock
     * renewal starts for every kept message as soon as it is received, not when its turn comes.
     */
    void handle(List<Leased> batch) {
        if (batch == null || batch.isEmpty()) {
            return;
        }
        List<Leased> keep = batch;
        if (batch.size() > RECEIVE_MAX) {
            keep = batch.subList(0, RECEIVE_MAX);
            List<Leased> extras = batch.subList(RECEIVE_MAX, batch.size());
            log.warn("Agent gateway returned {} messages for max={}; abandoning {} extra for redelivery",
                    batch.size(), RECEIVE_MAX, extras.size());
            for (Leased extra : extras) {
                safely(() -> client.abandon(extra));
            }
        }
        List<ScheduledFuture<?>> renewals = new ArrayList<>(keep.size());
        for (Leased m : keep) {
            renewals.add(scheduleRenewal(m));
        }
        try {
            for (int i = 0; i < keep.size(); i++) {
                dispatch(keep.get(i), renewals.get(i));
            }
        } finally {
            for (ScheduledFuture<?> renewal : renewals) {
                if (renewal != null) {
                    renewal.cancel(false);
                }
            }
        }
    }

    void dispatch(Leased m) {
        dispatch(m, scheduleRenewal(m));
    }

    private void dispatch(Leased m, ScheduledFuture<?> renewal) {
        HttpInboundContext context = new HttpInboundContext(client, m);
        try {
            listener.accept(context);
        } catch (RuntimeException e) {
            log.error("Listener failed on messageId={}; abandoning for redelivery", m.messageId(), e);
            if (!context.settled) {
                safely(() -> client.abandon(m));
            }
        } finally {
            if (renewal != null) {
                renewal.cancel(false);
            }
        }
    }

    private ScheduledFuture<?> scheduleRenewal(Leased m) {
        ScheduledExecutorService executor = renewer;
        if (executor == null || m.lockedUntil() == null) {
            return null;
        }
        long lockSeconds = Math.max(10, Duration.between(OffsetDateTime.now(), m.lockedUntil()).toSeconds());
        long every = Math.max(5, lockSeconds / 2);
        long deadline = System.nanoTime() + maxLockRenewal.toNanos();
        return executor.scheduleAtFixedRate(() -> {
            if (System.nanoTime() < deadline) {
                safely(() -> client.renewLock(m));
            }
        }, every, every, TimeUnit.SECONDS);
    }

    private static void safely(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException e) {
            log.debug("Gateway call failed: {}", e.getMessage());
        }
    }

    private static boolean sleep(Duration d) {
        try {
            Thread.sleep(d.toMillis());
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Settlement over HTTPS. A lost lock is not an error: the server will redeliver. */
    static final class HttpInboundContext implements InboundContext {
        private final GatewayClient client;
        private final Leased leased;
        private final LeasedMessage message;
        volatile boolean settled;

        HttpInboundContext(GatewayClient client, Leased leased) {
            this.client = client;
            this.leased = leased;
            this.message = new LeasedMessage(leased);
        }

        @Override
        public InboundMessage getMessage() {
            return message;
        }

        @Override
        public String getEntityPath() {
            return "agent-gateway/notifications";
        }

        @Override
        public void complete() {
            settled = true;
            if (!client.complete(leased)) {
                throw new IllegalStateException("lock lost before complete; the message will be redelivered");
            }
        }

        @Override
        public void abandon() {
            settled = true;
            client.abandon(leased);
        }

        @Override
        public void deadLetter(DeadLetterOptions options) {
            settled = true;
            client.deadLetter(leased, options == null ? null : options.getDeadLetterReason(),
                    options == null ? null : options.getDeadLetterErrorDescription());
        }
    }
}
