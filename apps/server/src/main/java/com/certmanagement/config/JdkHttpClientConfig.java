// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * One JDK {@link HttpClient} for the services that call third parties with plain
 * {@link java.net.http.HttpRequest}s. The client holds the connection pool and
 * its own threads, so one shared instance beats one per service; per-request timeouts stay on
 * each request.
 */
@Configuration
public class JdkHttpClientConfig {

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    @Bean
    public HttpClient jdkHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }
}
