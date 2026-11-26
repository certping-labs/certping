// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class IntegrationProviderTest {

    @Test
    void isWebhookProvider() {
        assertThat(IntegrationProvider.SLACK.isWebhookProvider()).isTrue();
        assertThat(IntegrationProvider.TEAMS.isWebhookProvider()).isTrue();
        assertThat(IntegrationProvider.PAGERDUTY.isWebhookProvider()).isFalse();
        assertThat(IntegrationProvider.SERVICENOW_ITSM.isWebhookProvider()).isFalse();
    }

    @Test
    void supportsIncidentCreation() {
        assertThat(IntegrationProvider.PAGERDUTY.supportsIncidentCreation()).isTrue();
        assertThat(IntegrationProvider.SERVICENOW_ITSM.supportsIncidentCreation()).isTrue();
        assertThat(IntegrationProvider.SLACK.supportsIncidentCreation()).isFalse();
        assertThat(IntegrationProvider.TEAMS.supportsIncidentCreation()).isFalse();
    }
}
