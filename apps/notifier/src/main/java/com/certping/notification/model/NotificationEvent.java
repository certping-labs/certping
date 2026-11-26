// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.model;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.enums.IntegrationType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;
import java.util.Map;

import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@JsonIgnoreProperties(ignoreUnknown = true)
@Builder(toBuilder = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class NotificationEvent {

    @JsonProperty("userId")
    private Long userId;

    @JsonProperty("organizationId")
    private Long organizationId;

    @JsonProperty("email")
    private String email;

    @JsonProperty("websiteId")
    private String websiteId;

    @JsonProperty("fullUrl")
    private String fullUrl;

    @JsonProperty("status")
    private String status;

    @JsonProperty("source")
    private String source;

    @JsonProperty("notificationType")
    private NotificationType notificationType;

    @JsonProperty("notificationAction")
    private NotificationAction notificationAction;

    @JsonProperty("integrationType")
    private IntegrationType integrationType;

    private Map<String, Object> templateFields;

    @JsonProperty("recipients")
    private List<String> recipients;

    /**
     * Addresses copied on an email: bare addresses at an allowed domain
     * ({@code notification.cc-allowed-domains}); others are dropped. They ride on one recipient's
     * message, the one whose lower-cased address sorts first, so they get no delivery, record or
     * deliver-once claim of their own, and once that recipient has the email a retry does not copy
     * them again.
     */
    @JsonProperty("cc")
    private List<String> cc;


    @JsonProperty("messageId")
    private String messageId;

    /**
     * The publisher's idempotency key for this notification. A publisher that does not send it
     * sends the key as {@code requestId}; see {@link #idempotencyKey()}.
     */
    @JsonProperty("notificationKey")
    private String notificationKey;

    /**
     * The idempotency key of a publisher that sends no {@code notificationKey}. The request that
     * caused the notification travels in the message's application properties, not here.
     */
    @JsonProperty("requestId")
    private String requestId;

    /** Publisher-supplied trace-level id, propagated onto the DB row for cross-
     *  service log correlation. Not used as a lookup key. */
    @JsonProperty("correlationId")
    private String correlationId;

    @JsonProperty("roles")
    private List<String> roles;

    /**
     * With {@code roles}: one more address beside the role holders, sent once when a role holder has
     * it too. The address may belong to someone who is not a member.
     */
    @JsonProperty("alsoTo")
    private String alsoTo;

    /**
     * With {@code roles} and {@code organizationId}: the role holders and also {@code userId}, while
     * that user is an active member of the organization. Each address receives the email once.
     */
    @JsonProperty("includeUser")
    private boolean includeUser;

    /**
     * Each recipient is delivered at most once per request id, tracked on a record of its own, and
     * the event is retried until every recipient has it.
     */
    @JsonProperty("deliverOnce")
    private boolean deliverOnce;

    /**
     * The stable identity of this notification, the natural key on {@code notification_records}: a
     * retry finds the row by it, so one row reflects the latest attempt.
     */
    public String idempotencyKey() {
        return notificationKey != null && !notificationKey.isBlank() ? notificationKey : requestId;
    }
}
