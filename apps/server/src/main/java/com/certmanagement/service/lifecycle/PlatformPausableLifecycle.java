// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * A feature whose records the platform pauses when a platform administrator switches it off and
 * resumes when it is switched back on. Driven by
 * {@link FeatureLifecycleReconciler}, inside a transaction holding the (organization, feature) lock.
 * Resumes are driven from {@code feature_lifecycle_state}, which every platform pause writes in the
 * same transaction, so the lifecycle only pages organizations with records to pause.
 */
public interface PlatformPausableLifecycle extends FeatureLifecycle {

    /**
     * What a pause would affect in each of a page of organizations (one grouped query), for the
     * baseline preview; organizations with nothing are absent.
     */
    Map<Long, List<AffectedItems>> activeItems(Collection<Long> organizationIds);

    /** One page of organizations, ascending after {@code afterOrganizationId}, with records to pause. */
    List<Long> organizationsWithActiveRecords(long afterOrganizationId, int limit);

    /**
     * Pauses every active record of the organization with reason PLATFORM. Idempotent: with nothing active it changes nothing.
     *
     * @return what was paused, one entry per kind with a count above zero
     */
    List<AffectedItems> platformPause(long organizationId);

    /**
     * Resumes the organization's PLATFORM-paused records (never USER ones), with their next runs
     * spread out. Idempotent.
     *
     * @return what was resumed, one entry per kind with a count above zero
     */
    List<AffectedItems> platformResume(long organizationId);
}
