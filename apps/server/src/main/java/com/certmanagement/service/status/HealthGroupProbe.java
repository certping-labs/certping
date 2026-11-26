// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Reads a Spring Boot health group of an internal service: up only on a 2xx whose body says
 * {@code "status":"UP"}. Built from {@link RestClient#builder()}, not the shared client or the Boot
 * builder, so no trace or MDC headers and no customizers ride along. Connect and read are each
 * bounded here; {@link PublicStatusRefresher} bounds the whole exchange, body included.
 */
@Slf4j
@Component
public class HealthGroupProbe {

    static final Duration TIMEOUT = Duration.ofSeconds(2);
    static final int MAX_BODY_BYTES = 1024;

    private final RestClient http;
    private final ObjectMapper objectMapper;

    @Autowired
    public HealthGroupProbe(ObjectMapper objectMapper) {
        this(objectMapper, TIMEOUT);
    }

    HealthGroupProbe(ObjectMapper objectMapper, Duration timeout) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(client);
        requestFactory.setReadTimeout(timeout);
        this.http = RestClient.builder().requestFactory(requestFactory).build();
        this.objectMapper = objectMapper;
    }

    public boolean isUp(URI group) {
        try {
            Boolean up = http.get()
                    .uri(group)
                    .accept(MediaType.APPLICATION_JSON)
                    .exchange((request, response) ->
                            response.getStatusCode().is2xxSuccessful() && reportsUp(response.getBody()));
            return Boolean.TRUE.equals(up);
        } catch (RestClientException | JacksonException e) {
            log.debug("Status probe of {} failed: {}", group, e.toString());
            return false;
        }
    }

    private boolean reportsUp(InputStream body) throws IOException {
        byte[] bytes = body.readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) {
            return false;
        }
        JsonNode status = objectMapper.readTree(bytes).path("status");
        return status.isString() && "UP".equals(status.stringValue());
    }
}
