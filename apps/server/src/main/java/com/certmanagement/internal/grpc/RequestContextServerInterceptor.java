// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import io.grpc.Context;
import io.grpc.ForwardingServerCall;
import io.grpc.ForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.function.Supplier;

/**
 * Puts the caller's {@code x-request-id} and {@code x-correlation-id} into the MDC for every
 * callback of a call, so its log lines carry the same ids as the caller's, and logs one
 * line per call. Trace context ({@code traceparent}) is picked up by the OpenTelemetry agent.
 *
 * <p>The contract requires a deadline on every call. One that arrives without is served anyway and
 * counted, because refusing it would only surface as an outage of the caller.
 */
@Slf4j
@Component
public class RequestContextServerInterceptor implements ServerInterceptor {

    static final Metadata.Key<String> REQUEST_ID = Metadata.Key.of("x-request-id", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> CORRELATION_ID = Metadata.Key.of("x-correlation-id", Metadata.ASCII_STRING_MARSHALLER);

    private final MeterRegistry meters;
    private final Counter missingDeadline;

    public RequestContextServerInterceptor(MeterRegistry meters) {
        this.meters = meters;
        this.missingDeadline = Counter.builder("certping.internal.grpc.missing.deadline")
                .description("Internal gRPC calls that arrived without a deadline")
                .register(meters);
    }

    @Override
    public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
        String requestId = orElse(headers.get(REQUEST_ID), () -> "grpc-" + UUID.randomUUID());
        String correlationId = orElse(headers.get(CORRELATION_ID), () -> requestId);
        String method = call.getMethodDescriptor().getFullMethodName();
        long startedNanos = System.nanoTime();
        if (Context.current().getDeadline() == null) {
            missingDeadline.increment();
        }

        ServerCall<Q, R> logged = new ForwardingServerCall.SimpleForwardingServerCall<>(call) {
            @Override
            public void close(Status status, Metadata trailers) {
                long millis = (System.nanoTime() - startedNanos) / 1_000_000;
                meters.counter("certping.internal.grpc.calls", "method", method, "status", status.getCode().name()).increment();
                if (status.isOk()) {
                    log.info("[INTERNAL_GRPC] method={} status=OK ms={}", method, millis);
                } else {
                    log.warn("[INTERNAL_GRPC] method={} status={} ms={} description={}",
                            method, status.getCode(), millis, status.getDescription());
                }
                super.close(status, trailers);
            }
        };
        ServerCall.Listener<Q> listener = withIds(requestId, correlationId, () -> next.startCall(logged, headers));
        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
            @Override
            public void onMessage(Q message) {
                withIds(requestId, correlationId, () -> super.onMessage(message));
            }

            @Override
            public void onHalfClose() {
                withIds(requestId, correlationId, super::onHalfClose);
            }

            @Override
            public void onCancel() {
                withIds(requestId, correlationId, super::onCancel);
            }

            @Override
            public void onComplete() {
                withIds(requestId, correlationId, super::onComplete);
            }

            @Override
            public void onReady() {
                withIds(requestId, correlationId, super::onReady);
            }
        };
    }

    private static void withIds(String requestId, String correlationId, Runnable body) {
        withIds(requestId, correlationId, () -> {
            body.run();
            return null;
        });
    }

    private static <T> T withIds(String requestId, String correlationId, Supplier<T> body) {
        MDC.put("requestId", requestId);
        MDC.put("correlationId", correlationId);
        try {
            return body.get();
        } finally {
            MDC.remove("requestId");
            MDC.remove("correlationId");
        }
    }

    private static String orElse(String value, Supplier<String> fallback) {
        return value == null || value.isBlank() ? fallback.get() : value;
    }
}
