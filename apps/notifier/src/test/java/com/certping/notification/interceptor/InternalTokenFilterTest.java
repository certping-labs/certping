// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.interceptor;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Every notifier endpoint but health answers only the internal token. */
class InternalTokenFilterTest {

    private static final String TOKEN = "internal-token-value";

    private final InternalTokenFilter filter = new InternalTokenFilter(TOKEN);

    @ParameterizedTest
    @ValueSource(strings = {"/api/notifications", "/api/notifications/process",
            "/api/notifications/admin/replay-undelivered", "/actuator/info", "/actuator/prometheus", "/anything"})
    void everyEndpointWithoutTheTokenIs401(String path) throws Exception {
        for (String authorization : new String[] {null, "", "Bearer wrong", "Basic " + TOKEN, "Bearer " + TOKEN + "x"}) {
            MockHttpServletResponse response = call("POST", path, authorization);
            assertEquals(401, response.getStatus(), path + " with " + authorization);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/notifications", "/api/notifications/process", "/actuator/info"})
    void theTokenIsLetThrough(String path) throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request("GET", path, "Bearer " + TOKEN), response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/actuator/health", "/actuator/health/readiness", "/actuator/health/status"})
    void healthNeedsNoToken(String path) throws Exception {
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request("GET", path, null), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
    }

    @Test
    void withNoTokenConfiguredNothingButHealthIsAnswered() throws Exception {
        InternalTokenFilter unset = new InternalTokenFilter("");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        unset.doFilter(request("POST", "/api/notifications/process", "Bearer "), response, chain);

        assertEquals(401, response.getStatus());
        assertNull(chain.getRequest());
    }

    @Test
    void aLookalikeHealthPathIsNotExempt() throws Exception {
        assertEquals(401, call("GET", "/actuator/healthz", null).getStatus());
    }

    private MockHttpServletResponse call(String method, String path, String authorization) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> {
            throw new AssertionError("reached the endpoint without the token: " + path);
        };
        filter.doFilter(request(method, path, authorization), response, chain);
        return response;
    }

    private static MockHttpServletRequest request(String method, String path, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }
}
