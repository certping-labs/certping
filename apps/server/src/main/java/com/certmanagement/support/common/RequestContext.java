// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.util.StringUtils;

public final class RequestContext {

    public static final String REQUEST_ID_HEADER = "X-Request-Id";
    public static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    public static final String REQUEST_ID_KEY = "requestId";
    public static final String USER_ID_KEY = "userId";
    public static final String ORGANIZATION_ID_KEY = "organizationId";
    public static final String USER_ID_ATTR = RequestContext.class.getName() + ".userId";
    public static final String ORGANIZATION_ID_ATTR = RequestContext.class.getName() + ".organizationId";
    public static final String ERROR_CODE_ATTR = RequestContext.class.getName() + ".errorCode";
    public static final String AUTH_LATENCY_MS_ATTR = RequestContext.class.getName() + ".authLatencyMs";
    public static final String DOWNSTREAM_SERVICE_ATTR = RequestContext.class.getName() + ".downstreamService";
    public static final String DOWNSTREAM_STATUS_ATTR = RequestContext.class.getName() + ".downstreamStatus";
    public static final String DOWNSTREAM_LATENCY_MS_ATTR = RequestContext.class.getName() + ".downstreamLatencyMs";

    private RequestContext() {
    }

    public static String requestId(HttpServletRequest request) {
        String requestId = MDC.get(REQUEST_ID_KEY);
        if (StringUtils.hasText(requestId)) {
            return requestId;
        }

        String headerRequestId = request.getHeader(REQUEST_ID_HEADER);
        if (headerRequestId == null || headerRequestId.isBlank()) {
            headerRequestId = request.getHeader(CORRELATION_ID_HEADER);
        }
        return headerRequestId == null || headerRequestId.isBlank() ? "unknown" : headerRequestId;
    }

    public static String requestId(HttpServletRequest request, HttpServletResponse response) {
        if (response == null) {
            return requestId(request);
        }

        String requestId = response.getHeader(REQUEST_ID_HEADER);
        if (requestId != null && !requestId.isBlank()) {
            return requestId;
        }

        return requestId(request);
    }

    public static void recordErrorCode(HttpServletRequest request, String errorCode) {
        if (request != null && StringUtils.hasText(errorCode)) {
            request.setAttribute(ERROR_CODE_ATTR, errorCode);
        }
    }

    public static void recordAuthenticatedUser(HttpServletRequest request, Long userId, String organizationId) {
        if (request == null) {
            return;
        }
        if (userId != null) {
            request.setAttribute(USER_ID_ATTR, userId.toString());
        }
        if (StringUtils.hasText(organizationId)) {
            request.setAttribute(ORGANIZATION_ID_ATTR, organizationId);
        }
    }

    public static void recordAuthLatency(HttpServletRequest request, long latencyMs) {
        if (request != null) {
            request.setAttribute(AUTH_LATENCY_MS_ATTR, latencyMs);
        }
    }

    public static void recordDownstreamCall(HttpServletRequest request, String service, Integer status, long latencyMs) {
        if (request == null) {
            return;
        }

        if (StringUtils.hasText(service)) {
            request.setAttribute(DOWNSTREAM_SERVICE_ATTR, service);
        }
        if (status != null) {
            request.setAttribute(DOWNSTREAM_STATUS_ATTR, status);
        }
        request.setAttribute(DOWNSTREAM_LATENCY_MS_ATTR, latencyMs);
    }

    public static String stringAttribute(HttpServletRequest request, String attribute) {
        if (request == null) {
            return null;
        }

        Object value = request.getAttribute(attribute);
        return value instanceof String text && StringUtils.hasText(text) ? text : null;
    }

    public static Long longAttribute(HttpServletRequest request, String attribute) {
        if (request == null) {
            return null;
        }

        Object value = request.getAttribute(attribute);
        if (value instanceof Long longValue) {
            return longValue;
        }
        if (value instanceof Integer integerValue) {
            return integerValue.longValue();
        }
        return null;
    }

    public static Integer integerAttribute(HttpServletRequest request, String attribute) {
        if (request == null) {
            return null;
        }

        Object value = request.getAttribute(attribute);
        if (value instanceof Integer integerValue) {
            return integerValue;
        }
        if (value instanceof Long longValue) {
            return longValue.intValue();
        }
        return null;
    }

    public static HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servletAttributes) {
            return servletAttributes.getRequest();
        }

        return null;
    }
}
