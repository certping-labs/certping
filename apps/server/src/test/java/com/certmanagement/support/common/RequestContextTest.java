// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RequestContextTest {

    @AfterEach
    void tearDown() {
        MDC.clear();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void requestId_fromMdc() {
        MDC.put(RequestContext.REQUEST_ID_KEY, "mdc-req");
        assertThat(RequestContext.requestId(mock(HttpServletRequest.class))).isEqualTo("mdc-req");
    }

    @Test
    void requestId_fromRequestIdHeader() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(RequestContext.REQUEST_ID_HEADER)).thenReturn("hdr-req");
        assertThat(RequestContext.requestId(req)).isEqualTo("hdr-req");
    }

    @Test
    void requestId_fallsBackToCorrelationHeader() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(RequestContext.REQUEST_ID_HEADER)).thenReturn("");
        when(req.getHeader(RequestContext.CORRELATION_ID_HEADER)).thenReturn("corr-h");
        assertThat(RequestContext.requestId(req)).isEqualTo("corr-h");
    }

    @Test
    void requestId_unknownWhenNothingPresent() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        assertThat(RequestContext.requestId(req)).isEqualTo("unknown");
    }

    @Test
    void requestId_withResponse_nullResponseDelegates() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(RequestContext.REQUEST_ID_HEADER)).thenReturn("r");
        assertThat(RequestContext.requestId(req, null)).isEqualTo("r");
    }

    @Test
    void requestId_withResponse_usesResponseHeader() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getHeader(RequestContext.REQUEST_ID_HEADER)).thenReturn("resp-id");
        assertThat(RequestContext.requestId(req, resp)).isEqualTo("resp-id");
    }

    @Test
    void requestId_withResponse_blankResponseHeaderDelegates() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getHeader(RequestContext.REQUEST_ID_HEADER)).thenReturn("");
        when(req.getHeader(RequestContext.REQUEST_ID_HEADER)).thenReturn("from-req");
        assertThat(RequestContext.requestId(req, resp)).isEqualTo("from-req");
    }

    @Test
    void recordErrorCode_setsAttributeWhenPresent() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        RequestContext.recordErrorCode(req, "E1");
        verify(req).setAttribute(RequestContext.ERROR_CODE_ATTR, "E1");
        RequestContext.recordErrorCode(null, "E1"); // no NPE
        RequestContext.recordErrorCode(req, "   "); // blank ignored
    }

    @Test
    void recordAuthenticatedUser_setsUserAndOrg() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        RequestContext.recordAuthenticatedUser(req, 9L, "org-1");
        verify(req).setAttribute(RequestContext.USER_ID_ATTR, "9");
        verify(req).setAttribute(RequestContext.ORGANIZATION_ID_ATTR, "org-1");
        RequestContext.recordAuthenticatedUser(null, 1L, "o"); // no NPE
    }

    @Test
    void recordAuthLatency_andDownstream() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        RequestContext.recordAuthLatency(req, 12L);
        verify(req).setAttribute(RequestContext.AUTH_LATENCY_MS_ATTR, 12L);
        RequestContext.recordAuthLatency(null, 1L);

        RequestContext.recordDownstreamCall(req, "svc", 200, 5L);
        verify(req).setAttribute(RequestContext.DOWNSTREAM_SERVICE_ATTR, "svc");
        verify(req).setAttribute(RequestContext.DOWNSTREAM_STATUS_ATTR, 200);
        verify(req).setAttribute(RequestContext.DOWNSTREAM_LATENCY_MS_ATTR, 5L);
        RequestContext.recordDownstreamCall(null, "x", 1, 1L);
    }

    @Test
    void stringAttribute_branches() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getAttribute("a")).thenReturn("val");
        when(req.getAttribute("b")).thenReturn(123);
        assertThat(RequestContext.stringAttribute(req, "a")).isEqualTo("val");
        assertThat(RequestContext.stringAttribute(req, "b")).isNull();
        assertThat(RequestContext.stringAttribute(null, "a")).isNull();
    }

    @Test
    void longAttribute_branches() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getAttribute("l")).thenReturn(5L);
        when(req.getAttribute("i")).thenReturn(7);
        when(req.getAttribute("s")).thenReturn("x");
        assertThat(RequestContext.longAttribute(req, "l")).isEqualTo(5L);
        assertThat(RequestContext.longAttribute(req, "i")).isEqualTo(7L);
        assertThat(RequestContext.longAttribute(req, "s")).isNull();
        assertThat(RequestContext.longAttribute(null, "l")).isNull();
    }

    @Test
    void integerAttribute_branches() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getAttribute("i")).thenReturn(7);
        when(req.getAttribute("l")).thenReturn(9L);
        when(req.getAttribute("s")).thenReturn("x");
        assertThat(RequestContext.integerAttribute(req, "i")).isEqualTo(7);
        assertThat(RequestContext.integerAttribute(req, "l")).isEqualTo(9);
        assertThat(RequestContext.integerAttribute(req, "s")).isNull();
        assertThat(RequestContext.integerAttribute(null, "i")).isNull();
    }

    @Test
    void currentRequest_returnsRequestWhenBound() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));
        assertThat(RequestContext.currentRequest()).isSameAs(req);
    }

    @Test
    void currentRequest_nullWhenUnbound() {
        RequestContextHolder.resetRequestAttributes();
        assertThat(RequestContext.currentRequest()).isNull();
    }
}
