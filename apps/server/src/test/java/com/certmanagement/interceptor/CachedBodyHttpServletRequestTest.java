// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for {@link CachedBodyHttpServletRequest}. */
class CachedBodyHttpServletRequestTest {

    private CachedBodyHttpServletRequest wrap(String body) throws Exception {
        HttpServletRequest delegate = mock(HttpServletRequest.class);
        ByteArrayInputStream backing = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        ServletInputStream sis = new ServletInputStream() {
            @Override public boolean isFinished() { return backing.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener listener) { }
            @Override public int read() { return backing.read(); }
        };
        when(delegate.getInputStream()).thenReturn(sis);
        return new CachedBodyHttpServletRequest(delegate);
    }

    @Test
    void cachesBodyAndAllowsMultipleInputStreamReads() throws Exception {
        CachedBodyHttpServletRequest req = wrap("{\"a\":1}");

        byte[] first = req.getInputStream().readAllBytes();
        byte[] second = req.getInputStream().readAllBytes();

        assertThat(new String(first, StandardCharsets.UTF_8)).isEqualTo("{\"a\":1}");
        assertThat(second).isEqualTo(first);
        assertThat(req.getCachedBody()).isEqualTo(first);
    }

    @Test
    void getReaderReadsCachedBody() throws Exception {
        CachedBodyHttpServletRequest req = wrap("line-one");
        try (BufferedReader reader = req.getReader()) {
            assertThat(reader.readLine()).isEqualTo("line-one");
        }
    }

    @Test
    void inputStreamReportsReadyAndFinishedState() throws Exception {
        CachedBodyHttpServletRequest req = wrap("ab");
        ServletInputStream in = req.getInputStream();
        assertThat(in.isReady()).isTrue();
        assertThat(in.isFinished()).isFalse();
        in.readAllBytes();
        assertThat(in.isFinished()).isTrue();
    }

    @Test
    void setReadListenerIsUnsupported() throws Exception {
        CachedBodyHttpServletRequest req = wrap("x");
        ServletInputStream in = req.getInputStream();
        assertThatThrownBy(() -> in.setReadListener(mock(ReadListener.class)))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
