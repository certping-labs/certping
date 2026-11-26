// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;
import java.util.Set;

/**
 * What a read of the trail asks for, already resolved and validated: the scope, the window
 * (clamped by {@link AuditTrailReader}) and the filters. Every field but the window is optional;
 * {@code null} means "any". The store turns it into SQL and never trusts it for the scope: the
 * organization is the caller's own unless a super admin named one.
 *
 * @param view           which view of the trail; {@link AuditTrailView#ACTIVITY} when not set
 * @param visibility     platform view only: rows of this visibility; {@code null} for both
 * @param superAdmin     whether a super admin reads; only they may leave {@code organizationId} empty
 * @param organizationId the trail; {@code null} only for a super admin reading every organization
 * @param from           inclusive lower bound on {@code occurred_at}; {@code null} for none (super admins)
 * @param to             inclusive upper bound on {@code occurred_at}
 * @param action         a catalog action code ({@code action = ?})
 * @param events         rows of these event keys; an empty set matches nothing
 * @param hiddenFeatureKeys rows of these features are left out ({@link AuditVisibilityPolicy}); empty
 *                       under the current policy, which lists them marked {@code featureOff}
 * @param ascending      oldest first; newest first otherwise
 */
@Jacksonized
@Builder(toBuilder = true)
public record AuditEventQuery(
        AuditTrailView view,
        AuditVisibility visibility,
        boolean superAdmin,
        Long organizationId,
        Instant from,
        Instant to,
        Integer userId,
        AuditActorType actorType,
        String action,
        Set<String> events,
        AuditCategory category,
        String resourceType,
        Long resourceId,
        String resourceRef,
        String resourceName,
        AuditOutcome outcome,
        String requestId,
        String correlationId,
        Set<String> hiddenFeatureKeys,
        boolean ascending) {

    public AuditEventQuery {
        view = view == null ? AuditTrailView.ACTIVITY : view;
        events = events == null ? null : Set.copyOf(events);
        hiddenFeatureKeys = hiddenFeatureKeys == null ? Set.of() : Set.copyOf(hiddenFeatureKeys);
    }
}
