// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewScope;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link AutoRenewLifecycle} the platform pauses: a super admin's switch-off holds the
 * organization's automatic renewals within its scope ({@code renewal_schedule.enabled = false} with
 * {@code last_renewal_status} set to the hold status), and switching it back
 * on turns exactly those held schedules back on while their certificate is still usable.
 */
public class HeldRenewalsLifecycle extends AutoRenewLifecycle implements PlatformPausableLifecycle {

    private final String holdStatus;

    /**
     * @param holdStatus the {@code last_renewal_status} that marks a schedule this feature held
     */
    public HeldRenewalsLifecycle(String featureKey, BlockerKind kind, String label, AutoRenewScope renewals,
                                 String holdStatus, CertificateLifecycleRepository certificates) {
        super(featureKey, kind, label, renewals, certificates);
        this.holdStatus = holdStatus;
    }

    @Override
    public Map<Long, List<AffectedItems>> activeItems(Collection<Long> organizationIds) {
        Map<Long, List<AffectedItems>> items = new HashMap<>();
        certificates.countAutoRenewByOrganization(organizationIds, renewals).forEach((organizationId, count) ->
                items.put(organizationId, affected(Math.toIntExact(count))));
        return items;
    }

    @Override
    public List<Long> organizationsWithActiveRecords(long afterOrganizationId, int limit) {
        return certificates.organizationsWithAutoRenew(afterOrganizationId, limit, renewals);
    }

    @Override
    public List<AffectedItems> platformPause(long organizationId) {
        return affected(certificates.holdAutoRenew(organizationId, renewals, holdStatus));
    }

    @Override
    public List<AffectedItems> platformResume(long organizationId) {
        return affected(certificates.releaseHeld(organizationId, holdStatus));
    }

    private List<AffectedItems> affected(int count) {
        return count == 0 ? List.of() : List.of(new AffectedItems(kind, label, count));
    }
}
