// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certmanagement.internal.v1.AllowsNotificationRequest;
import com.certmanagement.internal.v1.AllowsNotificationResponse;
import com.certmanagement.internal.v1.NotificationPolicyServiceGrpc;
import com.certmanagement.internal.v1.NotificationPolicyServiceGrpc.NotificationPolicyServiceBlockingStub;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.utils.MessageIds;
import com.certping.notification.utils.RequestContextLogger;
import io.grpc.Channel;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthCheckResponse;
import io.grpc.health.v1.HealthGrpc;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import io.grpc.stub.StreamObserver;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Asks the server's {@code NotificationPolicyService} whether an organization turned off an event's
 * category. Only events addressed to an organization are asked; auth and platform emails never are.
 *
 * <p>One attempt with a 1-second deadline, and any failure delivers: a lost answer must never cost a
 * notification, and the call never holds a delivery longer than that. Failures are counted
 * ({@value #CHECK_FAILED_METRIC}, tagged with the gRPC status) for the hub's alert. With no
 * {@code CERT_MANAGER_GRPC_ADDR} nothing is asked and every event is delivered.
 *
 * <p>The channel connects at startup with one health check that nothing waits for, so the first
 * notification's deadline is not spent on name resolution, the connection and loading the call path.
 */
@Component
public class CertManagerNotificationPolicy implements NotificationPolicy, DisposableBean {

    static final Duration DEADLINE = Duration.ofSeconds(1);
    static final Duration WARM_UP_DEADLINE = Duration.ofSeconds(10);
    static final String CHECK_METRIC = "notification.preference_check";
    static final String CHECK_FAILED_METRIC = "notification.preference_check_failed";
    static final String SUPPRESSED_METRIC = "notification.suppressed";

    static final Metadata.Key<String> REQUEST_ID = Metadata.Key.of("x-request-id", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> CORRELATION_ID =
            Metadata.Key.of("x-correlation-id", Metadata.ASCII_STRING_MARSHALLER);

    /** Account, password and platform emails: never an organization's optional notice, so never asked. */
    private static final Set<NotificationAction> NEVER_ASKED = EnumSet.of(
            NotificationAction.PASSWORD_CHANGE_SUCCESS, NotificationAction.RESET_PASSWORD,
            NotificationAction.SYSTEM_DLQ_ALERT, NotificationAction.SYSTEM_QUEUE_DEPTH_WARNING,
            NotificationAction.SYSTEM_QUEUE_ALERT_RESOLVED);

    private final ManagedChannel ownedChannel;
    private final NotificationPolicyServiceBlockingStub stub;
    private final MeterRegistry meterRegistry;

    /** The internal token, sent on every call: the server refuses a call without it. */
    static final Metadata.Key<String> AUTHORIZATION = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    @Autowired
    public CertManagerNotificationPolicy(@Value("${notifier.cert-manager.grpc-address:}") String address,
                                         @Value("${notifier.transport.token:}") String token,
                                         MeterRegistry meterRegistry) {
        this(channelTo(address), token, meterRegistry);
        if (stub == null) {
            contextLogger().warn("CERT_MANAGER_GRPC_ADDR is not set: notification settings are not asked, "
                    + "every notification is delivered");
        }
    }

    /** A policy to {@code address} that sends no token; for tests. */
    CertManagerNotificationPolicy(String address, MeterRegistry meterRegistry) {
        this(address, "", meterRegistry);
    }

    /** A policy over {@code channel}, which the caller owns and shuts down; for tests. */
    CertManagerNotificationPolicy(Channel channel, MeterRegistry meterRegistry) {
        this(channel, null, "", meterRegistry);
    }

    /** A policy over {@code channel} sending {@code token}, which the caller owns and shuts down; for tests. */
    CertManagerNotificationPolicy(Channel channel, String token, MeterRegistry meterRegistry) {
        this(channel, null, token, meterRegistry);
    }

    private CertManagerNotificationPolicy(ManagedChannel owned, String token, MeterRegistry meterRegistry) {
        this(owned, owned, token, meterRegistry);
        if (owned != null) {
            warmUp(withToken(owned, token));
        }
    }

    private CertManagerNotificationPolicy(Channel channel, ManagedChannel owned, String token, MeterRegistry meterRegistry) {
        this.ownedChannel = owned;
        this.stub = channel == null ? null : NotificationPolicyServiceGrpc.newBlockingStub(withToken(channel, token));
        this.meterRegistry = meterRegistry;
    }

    /** {@code channel} with the token attached to every call; as is when there is no token. */
    static Channel withToken(Channel channel, String token) {
        if (token == null || token.isBlank()) {
            return channel;
        }
        Metadata headers = new Metadata();
        headers.put(AUTHORIZATION, "Bearer " + token.trim());
        return ClientInterceptors.intercept(channel, MetadataUtils.newAttachHeadersInterceptor(headers));
    }

    private static ManagedChannel channelTo(String address) {
        if (address == null || address.isBlank()) {
            return null;
        }
        return NettyChannelBuilder.forTarget(address.trim()).usePlaintext().build();
    }

    private static void warmUp(Channel channel) {
        HealthGrpc.newStub(channel)
                .withDeadlineAfter(WARM_UP_DEADLINE.toMillis(), TimeUnit.MILLISECONDS)
                .check(HealthCheckRequest.getDefaultInstance(), new StreamObserver<>() {
                    @Override
                    public void onNext(HealthCheckResponse response) {
                    }

                    @Override
                    public void onError(Throwable error) {
                        contextLogger().warn("cert-manager not reachable at startup ({}); until it is, notifications "
                                + "are sent without their organization's settings", Status.fromThrowable(error).getCode());
                    }

                    @Override
                    public void onCompleted() {
                    }
                });
    }

    @Override
    public Optional<String> suppressedCategory(NotificationEvent event) {
        if (stub == null || !asks(event)) {
            return Optional.empty();
        }
        Timer.Sample sample = Timer.start(meterRegistry);
        try {
            AllowsNotificationResponse answer = stub
                    .withDeadlineAfter(DEADLINE.toMillis(), TimeUnit.MILLISECONDS)
                    .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(ids(event)))
                    .allowsNotification(AllowsNotificationRequest.newBuilder()
                            .setOrganizationId(event.getOrganizationId())
                            .setAction(event.getNotificationAction().name())
                            .build());
            if (answer.getAllowed()) {
                sample.stop(meterRegistry.timer(CHECK_METRIC, "outcome", "allowed"));
                return Optional.empty();
            }
            String category = answer.getCategory().isBlank() ? "UNKNOWN" : answer.getCategory();
            sample.stop(meterRegistry.timer(CHECK_METRIC, "outcome", "suppressed"));
            meterRegistry.counter(SUPPRESSED_METRIC, "action", event.getNotificationAction().name(),
                    "category", category).increment();
            return Optional.of(category);
        } catch (RuntimeException e) {
            sample.stop(meterRegistry.timer(CHECK_METRIC, "outcome", "failed"));
            String reason = Status.fromThrowable(e).getCode().name();
            meterRegistry.counter(CHECK_FAILED_METRIC, "reason", reason).increment();
            contextLogger().warn("Notification settings not readable ({}) for organization {}, action {}; delivering",
                    reason, event.getOrganizationId(), event.getNotificationAction());
            return Optional.empty();
        }
    }

    /** Whether the event is an organization's notification its settings may turn off. */
    static boolean asks(NotificationEvent event) {
        return event.getOrganizationId() != null && event.getOrganizationId() > 0
                && event.getNotificationAction() != null
                && !NEVER_ASKED.contains(event.getNotificationAction());
    }

    private static Metadata ids(NotificationEvent event) {
        Metadata headers = new Metadata();
        String requestId = MessageIds.valid(event.idempotencyKey());
        if (requestId != null) {
            headers.put(REQUEST_ID, requestId);
        }
        String correlationId = MessageIds.valid(event.getCorrelationId());
        if (correlationId != null) {
            headers.put(CORRELATION_ID, correlationId);
        }
        return headers;
    }

    @Override
    public void destroy() throws InterruptedException {
        if (ownedChannel != null) {
            ownedChannel.shutdown();
            if (!ownedChannel.awaitTermination(5, TimeUnit.SECONDS)) {
                ownedChannel.shutdownNow();
            }
        }
    }

    private static Logger contextLogger() {
        return RequestContextLogger.getLogger(CertManagerNotificationPolicy.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
