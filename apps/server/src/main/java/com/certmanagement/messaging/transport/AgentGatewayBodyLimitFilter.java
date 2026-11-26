// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Caps request bodies on the agent gateway ({@code /api/v1/agent-gateway/**}) before anything reads them:
 * ahead of {@link com.certmanagement.interceptor.RequestBodyCachingFilter}, which buffers JSON bodies, and
 * of Jackson. A declared {@code Content-Length} over {@link TransportProperties#getMaxRequestBodyBytes()} is
 * answered 413 at once; a chunked body is counted while it is read and fails the same way at the limit.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AgentGatewayBodyLimitFilter extends OncePerRequestFilter {

    private final TransportProperties properties;

    public AgentGatewayBodyLimitFilter(TransportProperties properties) {
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path == null || !(path.equals(AgentGatewayHeaders.BASE_PATH)
                || path.startsWith(AgentGatewayHeaders.BASE_PATH + "/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long limit = properties.getMaxRequestBodyBytes();
        if (request.getContentLengthLong() > limit) {
            log.warn("Agent gateway request refused: declared body of {} bytes is over the {} byte limit",
                    request.getContentLengthLong(), limit);
            tooLarge(response);
            return;
        }
        try {
            chain.doFilter(new CappedBodyRequest(request, limit), response);
        } catch (BodyTooLargeException | ServletException e) {
            if (!(e instanceof BodyTooLargeException) && !causedByTooLarge(e)) {
                throw e;
            }
            log.warn("Agent gateway request refused: body over the {} byte limit", limit);
            if (!response.isCommitted()) {
                response.resetBuffer();
                tooLarge(response);
            }
        }
    }

    private static boolean causedByTooLarge(Throwable e) {
        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
            if (cause instanceof BodyTooLargeException) {
                return true;
            }
        }
        return false;
    }

    private static void tooLarge(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"status\":413,\"error\":\"Payload Too Large\",\"message\":\"request body is too large\"}");
    }

    /** Thrown by the capped stream once more than the limit has been read. */
    static final class BodyTooLargeException extends IOException {
        BodyTooLargeException() {
            super("request body is over the agent gateway limit");
        }
    }

    private static final class CappedBodyRequest extends HttpServletRequestWrapper {
        private final long limit;
        private ServletInputStream stream;

        CappedBodyRequest(HttpServletRequest request, long limit) {
            super(request);
            this.limit = limit;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new CappedInputStream(super.getInputStream(), limit);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    private static final class CappedInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long limit;
        private long read;

        CappedInputStream(ServletInputStream delegate, long limit) {
            this.delegate = delegate;
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) {
                count(1);
            }
            return b;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int n = delegate.read(buffer, offset, length);
            if (n > 0) {
                count(n);
            }
            return n;
        }

        private void count(int n) throws BodyTooLargeException {
            read += n;
            if (read > limit) {
                throw new BodyTooLargeException();
            }
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            delegate.setReadListener(listener);
        }
    }
}
