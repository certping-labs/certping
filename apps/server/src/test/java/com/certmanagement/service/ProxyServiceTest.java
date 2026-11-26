// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.GatewayRequestContext;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProxyServiceTest {

    private static final String BASE = "http://notif.local";

    @Mock private RestTemplate restTemplate;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private ProxyService service;

    @BeforeEach
    void setUp() {
        service = new ProxyService(restTemplate, objectMapper, BASE);
        GatewayRequestContext.clear();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private void setContext() {
        GatewayRequestContext.set(7, "org-9", "req-1", "u@x.io");
        GatewayRequestContext.setCorrelationId("corr-2");
    }

    // ===== enrichJsonBody =====

    @Test
    void enrichJsonBody_noContext_returnsOriginal() {
        assertThat(service.enrichJsonBody("{\"a\":1}")).isEqualTo("{\"a\":1}");
    }

    @Test
    void enrichJsonBody_withContext_injectsFieldsAndOwner() throws Exception {
        setContext();
        String out = service.enrichJsonBody("{\"a\":1}");

        Map<?, ?> map = objectMapper.readValue(out, Map.class);
        assertThat(map.get("userId")).isEqualTo(7);
        assertThat(map.get("organizationId")).isEqualTo("org-9");
        assertThat(map.get("requestId")).isEqualTo("req-1");
        assertThat(map.get("email")).isEqualTo("u@x.io");
        assertThat(map.get("correlationId")).isEqualTo("corr-2");
        assertThat(map.get("a")).isEqualTo(1);

        @SuppressWarnings("unchecked")
        Map<String, Object> owner = (Map<String, Object>) map.get("owner");
        assertThat(owner.get("userId")).isEqualTo(7);
        assertThat(owner.get("organizationId")).isEqualTo("org-9");
    }

    @Test
    void enrichJsonBody_blankBody_createsMapWithContext() throws Exception {
        setContext();
        String out = service.enrichJsonBody("");
        Map<?, ?> map = objectMapper.readValue(out, Map.class);
        assertThat(map.get("userId")).isEqualTo(7);
    }

    @Test
    void enrichJsonBody_preservesExistingOwnerMap() throws Exception {
        setContext();
        String out = service.enrichJsonBody("{\"owner\":{\"role\":\"admin\"}}");
        Map<?, ?> map = objectMapper.readValue(out, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> owner = (Map<String, Object>) map.get("owner");
        assertThat(owner.get("role")).isEqualTo("admin");
        assertThat(owner.get("userId")).isEqualTo(7);
    }

    @Test
    void enrichJsonBody_invalidJson_returnsOriginal() {
        setContext();
        assertThat(service.enrichJsonBody("not-json")).isEqualTo("not-json");
    }

    // ===== enrichQueryParams =====

    @Test
    void enrichQueryParams_noContext_returnsOriginal() {
        Map<String, String> in = new LinkedHashMap<>();
        in.put("x", "1");
        assertThat(service.enrichQueryParams(in)).isEqualTo(in);
    }

    @Test
    void enrichQueryParams_withContext_injects() {
        setContext();
        Map<String, String> out = service.enrichQueryParams(null);
        assertThat(out.get("userId")).isEqualTo("7");
        assertThat(out.get("organizationId")).isEqualTo("org-9");
        assertThat(out.get("requestId")).isEqualTo("req-1");
        assertThat(out.get("email")).isEqualTo("u@x.io");
        assertThat(out.get("correlationId")).isEqualTo("corr-2");
    }

    // ===== HTTP verbs: success / error / unexpected =====

    @Test
    void post_success_relaysBody() {
        when(restTemplate.exchange(eq(BASE + "/p"), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).body("ok"));

        ResponseEntity<String> resp = service.post("/p", "{}");
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(resp.getBody()).isEqualTo("ok");
    }

    @Test
    void post_httpStatusError_relaysError() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "bad", null, "err-body".getBytes(), null));

        ResponseEntity<String> resp = service.post("/p", "{}");
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).isEqualTo("err-body");
    }

    @Test
    void post_unexpectedError_returns500() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("boom"));

        ResponseEntity<String> resp = service.post("/p", "{}");
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(resp.getBody()).contains("Proxy error");
    }

    @Test
    void get_downstreamTimeout_returns504() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new ResourceAccessException("read timed out"));

        ResponseEntity<String> resp = service.get("/p", Map.of());
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.GATEWAY_TIMEOUT);
        assertThat(resp.getBody()).contains("timed out");
    }

    @Test
    void put_success_relaysBody() {
        when(restTemplate.exchange(eq(BASE + "/p"), eq(HttpMethod.PUT), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("ok"));
        assertThat(service.put("/p", "{}").getBody()).isEqualTo("ok");
    }

    @Test
    void put_unexpectedError_returns500() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.PUT), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("boom"));
        assertThat(service.put("/p", "{}").getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void get_withQueryParams_buildsUrlAndRelays() {
        setContext();
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("g"));

        Map<String, String> q = new LinkedHashMap<>();
        q.put("foo", "bar");
        assertThat(service.get("/g", q).getBody()).isEqualTo("g");
    }

    @Test
    void get_httpStatusError_relaysError() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.NOT_FOUND, "nf", null, "nope".getBytes(), null));
        assertThat(service.get("/g", null).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void delete_success_relays() {
        when(restTemplate.exchange(eq(BASE + "/d"), eq(HttpMethod.DELETE), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("d"));
        assertThat(service.delete("/d").getBody()).isEqualTo("d");
    }

    @Test
    void delete_unexpectedError_returns500() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.DELETE), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("boom"));
        assertThat(service.delete("/d").getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void deleteWithBody_success_relays() {
        when(restTemplate.exchange(eq(BASE + "/d"), eq(HttpMethod.DELETE), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("d"));
        assertThat(service.deleteWithBody("/d", "{}").getBody()).isEqualTo("d");
    }

    @Test
    void patch_success_relays() {
        when(restTemplate.exchange(eq(BASE + "/x"), eq(HttpMethod.PATCH), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("p"));
        assertThat(service.patch("/x", "{}").getBody()).isEqualTo("p");
    }

    @Test
    void patch_httpStatusError_relaysError() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.PATCH), any(HttpEntity.class), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.CONFLICT, "c", null, "dup".getBytes(), null));
        assertThat(service.patch("/x", "{}").getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void patchWithQueryParams_success_relays() {
        setContext();
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.PATCH), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("pq"));
        Map<String, String> q = new LinkedHashMap<>();
        q.put("k", "v");
        assertThat(service.patch("/x", "{}", q).getBody()).isEqualTo("pq");
    }

    @Test
    void patchWithQueryParams_unexpectedError_returns500() {
        when(restTemplate.exchange(any(String.class), eq(HttpMethod.PATCH), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("boom"));
        assertThat(service.patch("/x", "{}", null).getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
