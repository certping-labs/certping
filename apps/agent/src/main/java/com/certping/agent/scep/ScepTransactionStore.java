// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Per-transaction idempotency for the synchronous Intune flow. A retry of the same
 * {@code (endpointId, transactionID)} with the same CSR returns the cached CertRep; the same
 * transaction with a different CSR is a conflict. Expired entries are dropped opportunistically on
 * read and by a periodic sweep.
 */
public class ScepTransactionStore {

    private record Entry(String csrFingerprint, BinaryResponse response, Instant expiresAt) {
    }

    private record InFlight(String csrFingerprint, CompletableFuture<BinaryResponse> result) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final Map<String, InFlight> inFlight = new ConcurrentHashMap<>();
    private final Duration ttl;

    public ScepTransactionStore(AgentProperties properties) {
        this.ttl = properties.getScep().getTxnStateTtl();
    }

    public Optional<BinaryResponse> lookup(String endpointId, String transactionId, String csrFingerprint) {
        String key = key(endpointId, transactionId);
        Entry entry = entries.get(key);
        if (entry == null || entry.expiresAt().isBefore(Instant.now())) {
            entries.remove(key);
            return Optional.empty();
        }
        if (!entry.csrFingerprint().equals(csrFingerprint)) {
            throw new ScepConflictException("transactionID reused with a different CSR");
        }
        return Optional.of(entry.response());
    }

    /**
     * Coalesces concurrent deliveries of one source-scoped SCEP transaction. The first caller does
     * the validation and CA work; same-CSR followers receive its exact response, while a different
     * CSR using the same transaction id fails without reaching the CA.
     */
    public BinaryResponse execute(String endpointId, String transactionId, String csrFingerprint,
                                  Supplier<BinaryResponse> operation) {
        Optional<BinaryResponse> completed = lookup(endpointId, transactionId, csrFingerprint);
        if (completed.isPresent()) {
            return completed.get();
        }

        String key = key(endpointId, transactionId);
        InFlight candidate = new InFlight(csrFingerprint, new CompletableFuture<>());
        InFlight leader = inFlight.putIfAbsent(key, candidate);
        if (leader == null) {
            try {
                BinaryResponse response = operation.get();
                candidate.result().complete(response);
                return response;
            } catch (Throwable failure) {
                candidate.result().completeExceptionally(failure);
                throw propagate(failure);
            } finally {
                inFlight.remove(key, candidate);
            }
        }

        if (!leader.csrFingerprint().equals(csrFingerprint)) {
            throw new ScepConflictException("transactionID reused with a different CSR");
        }
        try {
            return leader.result().join();
        } catch (CompletionException failure) {
            throw propagate(failure.getCause());
        }
    }

    public void record(String endpointId, ScepRequest request, BinaryResponse response) {
        entries.put(key(endpointId, request.transactionId()),
                new Entry(request.csrFingerprint(), response, Instant.now().plus(ttl)));
    }

    /** Drop expired entries. Invoked periodically; also safe to call directly in tests. */
    @Scheduled(fixedDelay = 60_000L)
    public void evictExpired() {
        Instant now = Instant.now();
        entries.values().removeIf(e -> e.expiresAt().isBefore(now));
    }

    private static String key(String endpointId, String transactionId) {
        return endpointId + '|' + transactionId;
    }

    private static RuntimeException propagate(Throwable failure) {
        if (failure instanceof RuntimeException runtimeException) {
            return runtimeException;
        }
        if (failure instanceof Error error) {
            throw error;
        }
        return new IllegalStateException("SCEP transaction processing failed", failure);
    }
}
