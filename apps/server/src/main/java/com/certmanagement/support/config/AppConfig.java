// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration(proxyBeanMethods = false)
class AppConfig {

    /** Admin-configured webhook URLs: refused at connect time when they resolve to an internal address. */
    @Bean
    RestClient integrationWebhookRestClient(RestClient.Builder builder, IntegrationProperties properties,
                                            @Value("${app.integrations.allow-private-addresses:false}")
                                            boolean allowPrivateAddresses) {
        return builder
                .requestFactory(GuardedHttpClients.requestFactory(
                        properties.delivery().connectTimeout(),
                        properties.delivery().readTimeout(),
                        allowPrivateAddresses))
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    @Bean
    RestClient pagerDutyEventsRestClient(RestClient.Builder builder, IncidentsProperties properties) {
        return builder
                .baseUrl(properties.pagerduty().baseUrl().toString())
                .requestFactory(requestFactory(
                        properties.pagerduty().connectTimeout(),
                        properties.pagerduty().readTimeout(),
                        HttpClient.Redirect.NEVER))
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    private JdkClientHttpRequestFactory requestFactory(
            Duration connectTimeout,
            Duration readTimeout,
            HttpClient.Redirect redirectPolicy) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(redirectPolicy)
                .build();

        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(readTimeout);
        return requestFactory;
    }
}
