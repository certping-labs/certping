// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import com.certmanagement.internal.v1.AllowsNotificationRequest;
import com.certmanagement.internal.v1.AllowsNotificationResponse;
import com.certmanagement.internal.v1.NotificationPolicyServiceGrpc;
import com.certmanagement.service.notification.NotificationCategory;
import com.certmanagement.service.notification.NotificationPreferenceService;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * The notifier's question before it emails an organization: may this notification go out? Answers
 * from {@link NotificationPreferenceService#allows}, the same decision the organization's integrations
 * get, which never fails: an unreadable setting is an answer of true.
 */
@Component
public class NotificationPolicyGrpcService extends NotificationPolicyServiceGrpc.NotificationPolicyServiceImplBase {

    static final String SERVICE_NAME = NotificationPolicyServiceGrpc.SERVICE_NAME;

    private static final Pattern ACTION = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

    private final NotificationPreferenceService preferences;

    public NotificationPolicyGrpcService(NotificationPreferenceService preferences) {
        this.preferences = preferences;
    }

    @Override
    public void allowsNotification(AllowsNotificationRequest request,
                                   StreamObserver<AllowsNotificationResponse> response) {
        if (request.getOrganizationId() <= 0) {
            response.onError(invalid("organization_id must be positive"));
            return;
        }
        if (!ACTION.matcher(request.getAction()).matches()) {
            response.onError(invalid("action must be 1 to 64 of [A-Z0-9_], starting with a letter"));
            return;
        }
        boolean allowed = preferences.allows(request.getOrganizationId(), request.getAction());
        String category = allowed ? "" : NotificationCategory.of(request.getAction()).map(Enum::name).orElse("");
        response.onNext(AllowsNotificationResponse.newBuilder().setAllowed(allowed).setCategory(category).build());
        response.onCompleted();
    }

    private static RuntimeException invalid(String description) {
        return Status.INVALID_ARGUMENT.withDescription(description).asRuntimeException();
    }
}
