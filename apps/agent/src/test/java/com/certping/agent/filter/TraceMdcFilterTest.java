// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.filter;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class TraceMdcFilterTest {

    private final TraceMdcFilter filter = new TraceMdcFilter();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void populatesMdcFromHeaders_thenClearsAfterChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Request-ID", "req-abc");
        request.addHeader("X-Correlation-ID", "corr-xyz");
        request.addHeader("X-Message-ID", "msg-123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<String> reqDuring = new AtomicReference<>();
        AtomicReference<String> corrDuring = new AtomicReference<>();
        AtomicReference<String> msgDuring = new AtomicReference<>();
        FilterChain chain = (req, resp) -> {
            reqDuring.set(MDC.get("requestId"));
            corrDuring.set(MDC.get("correlationId"));
            msgDuring.set(MDC.get("messageId"));
        };

        filter.doFilter(request, response, chain);

        assertThat(reqDuring.get()).isEqualTo("req-abc");
        assertThat(corrDuring.get()).isEqualTo("corr-xyz");
        assertThat(msgDuring.get()).isEqualTo("msg-123");
        // Cleared after chain — pooled servlet threads must not leak IDs to the next request.
        assertThat(MDC.get("requestId")).isNull();
        assertThat(MDC.get("correlationId")).isNull();
        assertThat(MDC.get("messageId")).isNull();
        // Response echoes the resolved requestId.
        assertThat(response.getHeader("X-Request-ID")).isEqualTo("req-abc");
    }

    @Test
    void generatesRequestId_whenHeaderMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<String> reqDuring = new AtomicReference<>();
        FilterChain chain = (req, resp) -> reqDuring.set(MDC.get("requestId"));

        filter.doFilter(request, response, chain);

        // Fallback format is "req-http-<8-char-uuid>" — assert prefix + length without
        // pinning the random UUID itself.
        assertThat(reqDuring.get()).startsWith("req-http-").hasSize("req-http-".length() + 8);
        assertThat(response.getHeader("X-Request-ID")).isEqualTo(reqDuring.get());
    }

    @Test
    void clearsMdcEvenWhenChainThrows() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Request-ID", "req-fail");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, resp) -> {
            throw new RuntimeException("downstream blew up");
        };
        try {
            filter.doFilter(request, response, chain);
        } catch (Exception ignored) {
            // expected
        }
        // The finally block in TraceMdcFilter must still clear MDC so the next request on this
        // thread starts clean.
        assertThat(MDC.get("requestId")).isNull();
    }
}
