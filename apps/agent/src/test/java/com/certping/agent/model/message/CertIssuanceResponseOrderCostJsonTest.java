// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.config.ObjectMapperConfig;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The order-cost fields are optional on the wire, so agents and servers of either version keep working. */
class CertIssuanceResponseOrderCostJsonTest {

    private final ObjectMapper agentMapper = new ObjectMapperConfig().objectMapper();

    @Test
    void responseWithoutCost_leavesTheFieldsOut() throws Exception {
        JsonNode json = agentMapper.readTree(agentMapper.writeValueAsString(
                CertIssuanceResponse.builder().requestId("req-1").orderId("987").build()));

        assertThat(json.has("caOrderCost")).isFalse();
        assertThat(json.has("caOrderCurrency")).isFalse();
        assertThat(json.get("orderId").asString()).isEqualTo("987");
    }

    @Test
    void responseWithCost_sendsBothAsStrings() throws Exception {
        JsonNode json = agentMapper.readTree(agentMapper.writeValueAsString(
                CertIssuanceResponse.builder().orderId("12345").caOrderCost("210.00").caOrderCurrency("USD").build()));

        assertThat(json.get("caOrderCost").isString()).isTrue();
        assertThat(json.get("caOrderCost").asString()).isEqualTo("210.00");
        assertThat(json.get("caOrderCurrency").asString()).isEqualTo("USD");
    }

    @Test
    void responseWithCost_isReadByAReaderThatDoesNotKnowTheFields() throws Exception {
        String json = agentMapper.writeValueAsString(
                CertIssuanceResponse.builder().requestId("req-1").orderId("12345").caOrderCost("210.00").build());
        ObjectMapper olderReader = JsonMapper.builderWithJackson2Defaults()
                .disable(tools.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();

        ResponseBeforeOrderCost read = olderReader.readValue(json, ResponseBeforeOrderCost.class);

        assertThat(read.requestId).isEqualTo("req-1");
        assertThat(read.orderId).isEqualTo("12345");
    }

    /** The fields a receiver built before the order cost existed reads. */
    static class ResponseBeforeOrderCost {
        public String requestId;
        public String orderId;
    }
}
