// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

class TrailingSlashNormalizationFilterTest {

    private final TrailingSlashNormalizationFilter filter = new TrailingSlashNormalizationFilter();

    private HttpServletRequest runFilter(MockHttpServletRequest request) throws Exception {
        MockFilterChain chain = new MockFilterChain();
        ReflectionTestUtils.invokeMethod(
                filter, "doFilterInternal", request, new MockHttpServletResponse(), chain);
        return (HttpServletRequest) chain.getRequest();
    }

    @Test
    void rootPath_passesThroughUnwrapped() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
        HttpServletRequest forwarded = runFilter(request);
        assertThat(forwarded).isSameAs(request);
    }

    @Test
    void noTrailingSlash_passesThroughUnwrapped() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/integrations");
        HttpServletRequest forwarded = runFilter(request);
        assertThat(forwarded).isSameAs(request);
    }

    @Test
    void trailingSlash_strippedInWrapper() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/integrations/");
        request.setRequestURI("/api/v1/integrations/");
        HttpServletRequest forwarded = runFilter(request);
        assertThat(forwarded).isNotSameAs(request);
        assertThat(forwarded.getRequestURI()).isEqualTo("/api/v1/integrations");
        assertThat(forwarded.getRequestURL().toString()).doesNotEndWith("/");
        assertThat(forwarded.getServletPath()).isEqualTo("/api/v1/integrations");
    }

    @Test
    void trailingSlash_withContextPath_servletPathStripsContext() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ctx/api/alerts/");
        request.setRequestURI("/ctx/api/alerts/");
        request.setContextPath("/ctx");
        HttpServletRequest forwarded = runFilter(request);
        assertThat(forwarded.getRequestURI()).isEqualTo("/ctx/api/alerts");
        assertThat(forwarded.getServletPath()).isEqualTo("/api/alerts");
    }
}
