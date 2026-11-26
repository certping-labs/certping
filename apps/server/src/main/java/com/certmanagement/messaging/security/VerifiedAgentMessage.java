// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.security;

import java.time.OffsetDateTime;

/**
 * Trusted processing context for one authenticated agent message.
 *
 * <p>{@link #organizationId()} is the organization of the agent token that sent the message, which the
 * agent gateway stamped on it before the body was parsed. Handlers must scope every tenant read and write to
 * this value and must never re-derive the organization from the payload: the body is attacker-
 * controlled data, this record is not.
 *
 * <p>The gateway's stamp proves <em>who sent</em> the message. It does not prove that a
 * {@code certificateXref}, {@code sourceXref} or {@code requestId} inside the body belongs to that
 * organization, so ownership of a referenced object is a separate check.
 *
 * <p><b>Coverage today.</b> Certificate lookups are organization-scoped: a handler resolving a
 * {@code certificateXref} queries by xref <em>and</em> organization, so an authenticated sender
 * cannot reach another tenant's certificate. {@code sourceXref}, {@code syncXref} and
 * {@code requestId} are <em>not</em> yet scoped that way — the device-source, profile and
 * discovery handlers still resolve them by reference alone. What limits that today is the check
 * that the body's {@code organizationId} matches the declared one, which stops a sender naming a
 * different organization outright but does nothing about a reference belonging to one. Closing it
 * means giving those repositories organization-scoped lookups, the same treatment the certificate
 * repository already has.
 */
public record VerifiedAgentMessage(
        String organizationId,
        String messageType,
        String messageId,
        OffsetDateTime enqueuedAt,
        boolean verified,
        /* The agent token the gateway stamped on the message; null for a message without the stamp. */
        Long agentTokenId) {

    public VerifiedAgentMessage(String organizationId, String messageType, String messageId,
                                OffsetDateTime enqueuedAt, boolean verified) {
        this(organizationId, messageType, messageId, enqueuedAt, verified, null);
    }

    /**
     * Context for a message that did not come through the gateway (tests). The organization is the
     * body's unproven claim; handlers still scope
     * their queries to it, which prevents accidental cross-tenant writes but is not authentication.
     */
    public static VerifiedAgentMessage unverified(String claimedOrganizationId, String messageType,
                                                  String messageId, OffsetDateTime enqueuedAt) {
        return new VerifiedAgentMessage(claimedOrganizationId, messageType, messageId, enqueuedAt, false);
    }
}
