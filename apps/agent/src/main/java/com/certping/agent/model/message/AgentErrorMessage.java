// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

/**
 * Outbound message — agent → certping.
 * Published on any unrecoverable failure before dead-lettering the inbound message.
 */
@Data
@Builder
public class AgentErrorMessage {
    @Builder.Default
    private String messageType = "AGENT_ERROR";
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    /** Set for device-source sync failures so the server can fence the failure to the current run. */
    private String sourceXref;
    private String syncXref;
    private String originalMessageType;
    private String errorCode;
    private String errorDetail;
    private String respondedAt;

    /**
     * Wall-clock UTC instant (ISO-8601) at which the upstream said retry would succeed —
     * populated for {@code RETRY_GIVE_UP} when the last attempt's upstream supplied a
     * {@code Retry-After}. {@code null} for blind backoff give-ups (no hint was available)
     * and for first-try permanent failures. The server surfaces this to the user so the
     * UI can show "Try again after <time>" instead of "please retry later".
     */
    private String retryAfterUtc;

    /**
     * The underlying classifier code from the LAST attempt, when this {@code errorCode}
     * is the outer wrapper {@code RETRY_GIVE_UP}. Lets the server produce a specific
     * user-facing message (e.g. "LE rate-limited") instead of the generic give-up text.
     * {@code null} when {@code errorCode} is itself terminal.
     */
    private String lastReason;
}
