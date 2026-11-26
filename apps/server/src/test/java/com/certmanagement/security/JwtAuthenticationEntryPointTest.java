// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationEntryPointTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint(objectMapper,
            new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));

    @AfterEach
    void cleanup() {
        GatewayRequestContext.clear();
    }

    @Test
    void commence_writesUnauthorizedJsonBody() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/secure");
        req.setQueryString("a=b");
        req.addHeader("X-Request-ID", "req-99");
        req.addHeader("X-Correlation-ID", "corr-99");
        MockHttpServletResponse resp = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad token");

        entryPoint.commence(req, resp, ex);

        assertThat(resp.getStatus()).isEqualTo(401);
        assertThat(resp.getContentType()).contains("application/json");
        String body = resp.getContentAsString();
        assertThat(body).contains("\"error\":\"Unauthorized\"");
        assertThat(body).contains("\"message\":\"bad token\"");
        assertThat(body).contains("/api/secure?a=b");
        assertThat(body).contains("req-99");
        assertThat(body).contains("corr-99");
    }

    @Test
    void commence_usesGatewayContextIdsWhenPresent() throws Exception {
        GatewayRequestContext.set(1, "1", "ctx-req", "u@x.com");
        GatewayRequestContext.setCorrelationId("ctx-corr");
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/x");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        entryPoint.commence(req, resp, new BadCredentialsException("denied"));

        String body = resp.getContentAsString();
        assertThat(body).contains("ctx-req");
        assertThat(body).contains("ctx-corr");
    }

    @Test
    void commence_fallsBackToUnknownWhenNoIds() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/x");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        entryPoint.commence(req, resp, new BadCredentialsException("nope"));

        String body = resp.getContentAsString();
        assertThat(body).contains("\"requestId\":\"unknown\"");
        assertThat(body).contains("\"correlationId\":\"unknown\"");
    }
}
