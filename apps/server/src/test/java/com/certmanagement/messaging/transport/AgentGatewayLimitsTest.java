// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import com.certmanagement.service.FixedWindowRateLimiter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentGatewayLimitsTest {

    private final TransportProperties properties = new TransportProperties();
    private final FixedWindowRateLimiter rateLimiter = mock(FixedWindowRateLimiter.class);
    private final PostgresMessageQueue queue = mock(PostgresMessageQueue.class);
    private final AgentGatewayLimits limits = new AgentGatewayLimits(properties, rateLimiter, queue);

    private static void assert429(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(ResponseStatusException.class,
                e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
    }

    @Test
    void aTokenHoldsAtMostTheConfiguredLongPollsAndFreesThemWhenTheyEnd() {
        properties.setMaxConcurrentPollsPerToken(2);
        String key = AgentGatewayLimits.keyOf("cpa_token_one");
        List<AgentGatewayLimits.PollSlot> open = new ArrayList<>();
        open.add(limits.openPoll(key));
        open.add(limits.openPoll(key));

        assert429(() -> limits.openPoll(key));
        // Another token is not affected.
        limits.openPoll(AgentGatewayLimits.keyOf("cpa_token_two")).close();

        open.remove(0).close();
        limits.openPoll(key).close();
        open.forEach(AgentGatewayLimits.PollSlot::close);
        assertThat(limits.openPolls(key)).isZero();
    }

    @Test
    void requestsPerTokenAreCountedPerMinute() {
        properties.setMaxRequestsPerTokenPerMinute(5);
        when(rateLimiter.tryAcquire(anyString(), eq(5), eq(Duration.ofMinutes(1)))).thenReturn(OptionalLong.of(30));

        assert429(() -> limits.countRequest("abc", AgentGatewayLimits.RequestKind.POLL));
        verify(rateLimiter).tryAcquire(eq("agent-gateway-rate:abc"), eq(5), eq(Duration.ofMinutes(1)));
    }

    @Test
    void settleAndSendCallsHaveTheirOwnMuchHigherLimit() {
        properties.setMaxRequestsPerTokenPerMinute(5);
        properties.setMaxSettleRequestsPerTokenPerMinute(500);
        when(rateLimiter.tryAcquire(anyString(), anyInt(), any())).thenReturn(OptionalLong.empty());

        limits.countRequest("abc", AgentGatewayLimits.RequestKind.SETTLE);

        verify(rateLimiter).tryAcquire(eq("agent-gateway-rate-settle:abc"), eq(500), eq(Duration.ofMinutes(1)));
        verify(rateLimiter, never()).tryAcquire(eq("agent-gateway-rate:abc"), anyInt(), any());
    }

    @Test
    void aRateLimited429CarriesRetryAfterInSeconds() {
        when(rateLimiter.tryAcquire(anyString(), anyInt(), any())).thenReturn(OptionalLong.of(17));

        assertThatThrownBy(() -> limits.countRequest("abc", AgentGatewayLimits.RequestKind.SETTLE))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> {
                    assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                    assertThat(e.getHeaders().getFirst("Retry-After")).isEqualTo("17");
                });
    }

    @Test
    void thePollBackoffDoublesToItsCeilingAndResets() {
        PollBackoff backoff = new PollBackoff(Duration.ofMillis(250), Duration.ofSeconds(2));
        List<Long> pauses = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            pauses.add(backoff.nextPauseMillis());
        }
        assertThat(pauses).containsExactly(250L, 500L, 1000L, 2000L, 2000L, 2000L);
        backoff.reset();
        assertThat(backoff.nextPauseMillis()).isEqualTo(250L);
    }

    @Test
    void anOrganizationWithTooManyWaitingMessagesIsRefused() {
        properties.setMaxWaitingMessagesPerOrganization(100);
        when(queue.countWaiting("cert-agent-outbound", 7L, 100)).thenReturn(100);
        when(queue.countWaiting("cert-agent-outbound", 8L, 100)).thenReturn(99);

        assert429(() -> limits.checkQueueRoom("cert-agent-outbound", 7L));
        limits.checkQueueRoom("cert-agent-outbound", 8L);
    }

    @Test
    void theTokenKeyIsAHashNotTheToken() {
        assertThat(AgentGatewayLimits.keyOf("cpa_secret")).hasSize(32).doesNotContain("secret")
                .isEqualTo(AgentGatewayLimits.keyOf("cpa_secret"));
    }

    // ---------- body limit ----------

    @Test
    void aDeclaredBodyOverTheLimitIsA413BeforeAnythingReadsIt() throws Exception {
        properties.setMaxRequestBodyBytes(1024);
        AgentGatewayBodyLimitFilter filter = new AgentGatewayBodyLimitFilter(properties);
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/agent-gateway/messages");
        req.setContent(new byte[2048]);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(413);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void anUndeclaredBodyIsCutOffAtTheLimitWhileItIsRead() throws Exception {
        properties.setMaxRequestBodyBytes(1024);
        AgentGatewayBodyLimitFilter filter = new AgentGatewayBodyLimitFilter(properties);
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/agent-gateway/messages") {
            @Override
            public long getContentLengthLong() {
                return -1; // chunked
            }
        };
        req.setContent(new byte[4096]);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        doAnswer(invocation -> {
            ((jakarta.servlet.ServletRequest) invocation.getArgument(0)).getInputStream().readAllBytes();
            return null;
        }).when(chain).doFilter(any(), any());

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(413);
    }

    @Test
    void otherPathsAndSmallBodiesPass() throws Exception {
        properties.setMaxRequestBodyBytes(1024);
        AgentGatewayBodyLimitFilter filter = new AgentGatewayBodyLimitFilter(properties);
        FilterChain chain = mock(FilterChain.class);

        MockHttpServletRequest big = new MockHttpServletRequest("POST", "/api/v1/certs");
        big.setContent(new byte[4096]);
        filter.doFilter(big, new MockHttpServletResponse(), chain);
        MockHttpServletRequest small = new MockHttpServletRequest("POST", "/api/v1/agent-gateway/messages");
        small.setContent(new byte[100]);
        filter.doFilter(small, new MockHttpServletResponse(), chain);

        verify(chain, org.mockito.Mockito.times(2)).doFilter(any(), any());
        verify(rateLimiter, never()).tryAcquire(anyString(), anyInt(), any());
    }
}
