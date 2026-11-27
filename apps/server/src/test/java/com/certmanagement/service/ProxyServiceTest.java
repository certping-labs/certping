// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProxyServiceTest {

    private static final String BASE = "http://notif.local";

    @Mock private RestTemplate restTemplate;

    private ProxyService service;

    @BeforeEach
    void setUp() {
        service = new ProxyService(restTemplate, BASE);
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

    private URI requested() {
        ArgumentCaptor<URI> uri = ArgumentCaptor.forClass(URI.class);
        verify(restTemplate).exchange(uri.capture(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class));
        return uri.getValue();
    }

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
        assertThat(out).doesNotContainKeys("requestId", "email", "correlationId");
    }

    @Test
    void get_withQueryParams_buildsUrlAndRelays() {
        setContext();
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("g"));

        assertThat(service.get("/g", Map.of("foo", "bar")).getBody()).isEqualTo("g");

        URI uri = requested();
        assertThat(uri.getHost()).isEqualTo("notif.local");
        assertThat(uri.getPath()).isEqualTo("/g");
        assertThat(UriComponentsBuilder.fromUri(uri).build().getQueryParams().toSingleValueMap())
                .containsEntry("foo", "bar").containsEntry("organizationId", "org-9");
    }

    @Test
    void get_aValueCannotAddAnotherParameter() {
        setContext();
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("[]"));

        service.get("/g", Map.of("status", "SENT&organizationId=other#x"));

        var params = UriComponentsBuilder.fromUri(requested()).build(true).getQueryParams();
        assertThat(params.get("organizationId")).containsExactly("org-9");
        assertThat(params.getFirst("status")).isEqualTo("SENT%26organizationId%3Dother%23x");
    }

    @Test
    void get_aValueWithTemplateBracesIsEncoded() {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.ok("[]"));

        assertThat(service.get("/g", Map.of("status", "{x}")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(requested().getRawQuery()).isEqualTo("status=%7Bx%7D");
    }

    @Test
    void get_downstreamTimeout_returns504() {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new ResourceAccessException("read timed out"));

        ResponseEntity<String> resp = service.get("/p", Map.of());
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.GATEWAY_TIMEOUT);
        assertThat(resp.getBody()).contains("timed out");
    }

    @Test
    void get_httpStatusError_relaysError() {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.NOT_FOUND, "nf", null, "nope".getBytes(), null));
        ResponseEntity<String> resp = service.get("/g", null);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(resp.getBody()).isEqualTo("nope");
    }

    @Test
    void get_unexpectedError_returns500() {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("boom"));
        ResponseEntity<String> resp = service.get("/g", null);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(resp.getBody()).contains("Proxy error");
    }
}
