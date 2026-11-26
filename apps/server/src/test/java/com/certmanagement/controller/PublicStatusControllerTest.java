// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.service.status.DatabaseCheck;
import com.certmanagement.service.status.HealthGroupProbe;
import com.certmanagement.service.status.PublicStatusBoard;
import com.certmanagement.service.status.PublicStatusRefresher;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The public document over HTTP: 503 until the first round, the cache header, GET only, and a body
 * that holds only the documented keys and fixed values, whatever the checks threw.
 */
class PublicStatusControllerTest {

    private static final String PATH = "/api/v1/public/status";
    private static final String INTERNAL_FAILURE = "http://certping-agent:80 refused; jdbc:postgresql://pg-internal";
    private static final Set<String> IDS = Set.of("api", "notifications", "certificates");
    private static final Map<String, String> NAMES = Map.of(
            "api", "API and sign-in",
            "notifications", "Email notifications",
            "certificates", "Certificate issuance and renewal");
    private static final Set<String> STATUSES =
            Set.of("operational", "degraded_performance", "partial_outage", "major_outage");
    private static final Map<String, String> DESCRIPTIONS = Map.of(
            "none", "All systems operational",
            "minor", "Minor service disruption",
            "major", "Partial system outage",
            "critical", "Major system outage");
    private static final String RFC_3339_UTC = "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z";

    private final JsonMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final PublicStatusBoard board = new PublicStatusBoard(Clock.systemUTC(), java.time.Duration.ZERO);
    private final DatabaseCheck database = mock(DatabaseCheck.class);
    private final HealthGroupProbe probe = mock(HealthGroupProbe.class);
    private final PublicStatusRefresher refresher = new PublicStatusRefresher(board, database, probe,
            "http://certping-notifier:8080", "http://certping-agent");
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PublicStatusController(board))
            .setMessageConverters(new JacksonJsonHttpMessageConverter(objectMapper))
            .build();


    @Test
    void beforeTheFirstRoundIs503WithNothingCached() throws Exception {
        mvc.perform(get(PATH))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(content().string(""));
    }

    @Test
    void afterARoundIs200JsonCachedPubliclyForOneInterval() throws Exception {
        allUp();

        mvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=30"))
                .andExpect(content().contentType("application/json"));
    }

    @Test
    void outagesAreStill200WithTheStateInTheBody() throws Exception {
        when(database.answers()).thenReturn(false);
        when(probe.isUp(any())).thenReturn(false);
        refresher.refresh();

        MvcResult result = mvc.perform(get(PATH)).andExpect(status().isOk()).andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.at("/status/indicator").asString()).isEqualTo("critical");
    }

    @Test
    void manyRequestsInOneIntervalCostOneCheckEach() throws Exception {
        allUp();

        for (int i = 0; i < 200; i++) {
            mvc.perform(get(PATH)).andExpect(status().isOk());
        }

        verify(database, times(1)).answers();
        verify(probe, times(2)).isUp(any());
    }

    @Test
    void onlyGetIsMapped() throws Exception {
        allUp();

        mvc.perform(post(PATH)).andExpect(status().isMethodNotAllowed());
        mvc.perform(put(PATH)).andExpect(status().isMethodNotAllowed());
        mvc.perform(delete(PATH)).andExpect(status().isMethodNotAllowed());
    }

    @Test
    void theBodyHoldsOnlyDocumentedKeysAndFixedValues() throws Exception {
        when(database.answers()).thenThrow(new IllegalStateException(INTERNAL_FAILURE));
        when(probe.isUp(any())).thenThrow(new IllegalStateException(INTERNAL_FAILURE));
        refresher.refresh();
        assertAllowListed(mvc.perform(get(PATH)).andReturn());

        doReturn(true).when(database).answers();
        doReturn(true).when(probe).isUp(any());
        refresher.refresh();
        assertAllowListed(mvc.perform(get(PATH)).andReturn());
    }

    private void allUp() throws Exception {
        when(database.answers()).thenReturn(true);
        when(probe.isUp(any())).thenReturn(true);
        refresher.refresh();
    }

    private void assertAllowListed(MvcResult result) throws Exception {
        String raw = result.getResponse().getContentAsString();
        assertThat(raw).doesNotContain("certping-agent", "jdbc", "pg-internal", "http", "refused", "Exception");
        assertThat(result.getResponse().getHeaderNames())
                .allSatisfy(name -> assertThat(result.getResponse().getHeader(name)).doesNotContain("certping-agent"));

        JsonNode body = objectMapper.readTree(raw);
        assertThat(fieldNames(body)).containsExactlyInAnyOrder(
                "page", "status", "components", "incidents", "scheduled_maintenances");
        assertThat(fieldNames(body.get("page"))).containsExactly("updated_at");
        assertThat(body.at("/page/updated_at").asString()).matches(RFC_3339_UTC);
        assertThat(fieldNames(body.get("status"))).containsExactlyInAnyOrder("indicator", "description");
        String indicator = body.at("/status/indicator").asString();
        assertThat(DESCRIPTIONS).containsEntry(indicator, body.at("/status/description").asString());
        assertThat(body.get("incidents").isArray() && body.get("incidents").isEmpty()).isTrue();
        assertThat(body.get("scheduled_maintenances").isArray() && body.get("scheduled_maintenances").isEmpty())
                .isTrue();

        List<String> ids = new ArrayList<>();
        for (JsonNode component : body.get("components")) {
            assertThat(fieldNames(component)).containsExactlyInAnyOrder("id", "name", "status", "updated_at");
            String id = component.get("id").asString();
            ids.add(id);
            assertThat(IDS).contains(id);
            assertThat(component.get("name").asString()).isEqualTo(NAMES.get(id));
            assertThat(STATUSES).contains(component.get("status").asString());
            assertThat(component.get("updated_at").asString()).matches(RFC_3339_UTC);
        }
        assertThat(ids).containsExactly("api", "notifications", "certificates");
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.propertyNames().iterator().forEachRemaining(names::add);
        return names;
    }
}
