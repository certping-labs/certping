// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.interceptor.TraceHeaderForwardingInterceptor;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.util.Timeout;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder,
                                     TraceHeaderForwardingInterceptor traceHeaderInterceptor) {
        // Configure timeouts for HttpClient
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(10))
                .setResponseTimeout(Timeout.ofSeconds(30))
                .build();

        // Create HttpClient that supports PATCH requests with timeouts
        HttpClient httpClient = HttpClientBuilder.create()
                .setDefaultRequestConfig(requestConfig)
                .build();

        ClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        // Wrap with BufferingClientHttpRequestFactory to allow response body reading multiple times
        BufferingClientHttpRequestFactory bufferingFactory = new BufferingClientHttpRequestFactory(factory);

        // additionalInterceptors appends without overriding any caller-set interceptors. Every
        // outbound HTTP call made via this RestTemplate will carry X-Request-ID / X-Correlation-ID
        // / X-Message-ID populated from the current MDC, giving us end-to-end tracing across
        // service boundaries with no per-call wiring.
        return builder
                .requestFactory(() -> bufferingFactory)
                .additionalInterceptors(traceHeaderInterceptor)
                .build();
    }
}
