// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

class IncidentModelTest {

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void strictLongDeserializer_acceptsIntegerNumber() throws Exception {
        CreatePagerDutyIncidentRequest request = MAPPER.readValue(
                "{\"alertId\":12345,\"title\":\"t\",\"source\":\"s\",\"severity\":\"CRITICAL\"}",
                CreatePagerDutyIncidentRequest.class);
        assertThat(request.alertId()).isEqualTo(12345L);
    }

    @Test
    void strictLongDeserializer_acceptsNull() throws Exception {
        InternalPagerDutyIncidentPayload payload = MAPPER.readValue(
                "{\"alertId\":null,\"title\":\"t\",\"source\":\"s\",\"severity\":\"ERROR\"}",
                InternalPagerDutyIncidentPayload.class);
        assertThat(payload.alertId()).isNull();
    }

    @Test
    void strictLongDeserializer_rejectsStringNumber() {
        assertThatThrownBy(() -> MAPPER.readValue(
                "{\"alertId\":\"12345\",\"title\":\"t\",\"source\":\"s\",\"severity\":\"ERROR\"}",
                CreatePagerDutyIncidentRequest.class))
                .isInstanceOf(InvalidFormatException.class);
    }

    @Test
    void pagerDutySeverity_values() {
        assertThat(PagerDutyIncidentSeverity.CRITICAL.pagerDutyValue()).isEqualTo("critical");
        assertThat(PagerDutyIncidentSeverity.ERROR.pagerDutyValue()).isEqualTo("error");
        assertThat(PagerDutyIncidentSeverity.WARNING.pagerDutyValue()).isEqualTo("warning");
        assertThat(PagerDutyIncidentSeverity.INFO.pagerDutyValue()).isEqualTo("info");
    }

    @Test
    void serviceNowImpactAndUrgency_values() {
        assertThat(ServiceNowIncidentImpact.HIGH.serviceNowValue()).isEqualTo("1");
        assertThat(ServiceNowIncidentImpact.MEDIUM.serviceNowValue()).isEqualTo("2");
        assertThat(ServiceNowIncidentImpact.LOW.serviceNowValue()).isEqualTo("3");
        assertThat(ServiceNowIncidentUrgency.HIGH.serviceNowValue()).isEqualTo("1");
        assertThat(ServiceNowIncidentUrgency.LOW.serviceNowValue()).isEqualTo("3");
    }
}
