// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

/**
 * A write that may have switched {@code featureKey} on or off; published inside the writing
 * transaction. The feature lifecycle reconciles the affected organizations after it commits.
 *
 * @param organizationId the one organization affected, or {@code null} for every organization
 *                       (global and org-type writes)
 * @param actorUserId    the administrator who wrote it, or {@code null} outside a request
 * @param transitionId   the forced transition recorded for a super admin's change, or {@code null}
 *                       for an organization admin's own change (clear-first, never forced)
 */
public record FeatureFlagStateChangedEvent(String featureKey, Long organizationId, Integer actorUserId,
                                           Long transitionId) {
}
