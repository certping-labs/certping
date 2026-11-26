// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Whether an organization's integrations may deliver (Slack, Teams, PagerDuty, ServiceNow), by its
 * {@code INTEGRATIONS} flag. A delivery skipped because the flag is off is never silent: it is
 * counted ({@value #SKIPPED_METRIC}, tagged with the provider) and logged with the organization and
 * the integration. A flag that cannot be read lets the delivery through: paging must not drop on an
 * outage of the flag store.
 */
@Slf4j
@Component
public class IntegrationDeliveryGate {

    static final String SKIPPED_METRIC = "certping.integrations.delivery_skipped";

    private final FeatureFlagService featureFlags;
    private final MeterRegistry meters;

    public IntegrationDeliveryGate(FeatureFlagService featureFlags, MeterRegistry meters) {
        this.featureFlags = featureFlags;
        this.meters = meters;
    }

    /** Whether the organization's integrations may deliver now. */
    public boolean deliveryAllowed(long organizationId) {
        try {
            return featureFlags.isEnabled(FeatureFlags.INTEGRATIONS, organizationId);
        } catch (RuntimeException e) {
            log.warn("Integrations flag unreadable for orgId={}; delivering: {}", organizationId, e.getMessage());
            return true;
        }
    }

    /** Records one delivery to {@code integrationId} skipped because integrations are off. */
    public void recordSkipped(long organizationId, IntegrationProvider provider, Long integrationId, String action) {
        meters.counter(SKIPPED_METRIC, "kind", provider.name()).increment();
        log.info("Integration delivery skipped, integrations off: orgId={}, integrationId={}, provider={}, action={}",
                organizationId, integrationId, provider, action);
    }
}
