// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;

import java.util.UUID;

/**
 * Centralized read of the request-scoped IDs (requestId / correlationId) from SLF4J MDC.
 *
 * <p>By contract the IDs are minted at exactly two places in the server:
 * <ul>
 *   <li>{@code JwtAuthenticationFilter} — mints {@code requestId} for every authenticated HTTP
 *       request and seeds MDC. Reads {@code correlationId} from the {@code X-Correlation-ID}
 *       header (frontend-owned, never minted).</li>
 *   <li>{@code ScheduledMdcAspect} — mints {@code requestId} (only) for every {@code @Scheduled}
 *       tick. Never mints {@code correlationId} because scheduler ticks have no upstream caller.</li>
 * </ul>
 *
 * <p>Every other call site that needs an id (command builders, persistence events, etc.) must
 * call {@link #requestId()} or {@link #correlationId()} — never generate new values inline.
 * That guarantees one stable {@code requestId} per logical request flows end-to-end through
 * the message queue to the agent and back.
 *
 * <p>{@link #requestId()} returns an "orphan" fallback id (logged as a warning) when MDC is
 * unexpectedly empty — so the call still produces a working id but the gap is visible in logs.
 *
 * <p>{@link #correlationId()} returns {@code null} when MDC is empty or contains the legacy
 * {@code "unknown"} sentinel. In practice MDC carries a real value in two cases:
 * <ul>
 *   <li>HTTP entry: {@code RequestContextInterceptor} reads {@code X-Correlation-ID} from the
 *       request, or mints a {@code corr-http-} id when the frontend didn't supply one — so
 *       every HTTP-driven flow has a stable id that travels through the message queue to the agent and back.</li>
 *   <li>Scheduler entry: {@code DrainRunner} mints a {@code corr-cron-} id for each drain run;
 *       admin HTTP triggers inherit the {@code corr-http-} id minted at the interceptor.</li>
 * </ul>
 *
 * <p>Backend-minted ids carry a prefix ({@code corr-http-} / {@code corr-cron-}) so log
 * analysis can distinguish them from frontend-provided ones (no prefix or app-specific prefix).
 */
@Slf4j
public final class MdcIds {

    private MdcIds() {
        // utility class
    }

    /**
     * Request-scoped id, sourced from MDC. Falls back to a marked "orphan" id (with a warning)
     * if MDC is empty — this should never happen in practice; it indicates a missed entry-point
     * seeder (HTTP filter / scheduler aspect / queue worker).
     */
    public static String requestId() {
        String req = MDC.get("requestId");
        if (req != null && !req.isEmpty()) {
            return req;
        }
        String fallback = "req-orphan-" + UUID.randomUUID().toString().substring(0, 8);
        log.warn("MdcIds.requestId() — no requestId in MDC at call site; minting orphan={}", fallback);
        return fallback;
    }

    /**
     * Correlation id, sourced from MDC. Returns {@code null} when MDC is empty (or set to the
     * sentinel {@code "unknown"} used by {@code RequestContextInterceptor} when the frontend
     * omitted {@code X-Correlation-ID}) — by contract we never fabricate a correlation id.
     */
    public static String correlationId() {
        String corr = MDC.get("correlationId");
        return (corr == null || corr.isEmpty() || "unknown".equals(corr)) ? null : corr;
    }
}
