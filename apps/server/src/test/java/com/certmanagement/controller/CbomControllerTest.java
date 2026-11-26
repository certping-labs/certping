// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.cbom.CbomProjectionService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.io.OutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;

@ExtendWith(MockitoExtension.class)
class CbomControllerTest {

    @Mock
    private CbomProjectionService cbomProjectionService;

    @InjectMocks
    private CbomController cbomController;

    private static final Long ORG_ID = 7L;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void downloadCbom_streamsTheOrganizationsCbomAsAJsonAttachment() throws IOException {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "user@test.com");
        doAnswer(invocation -> {
            invocation.<OutputStream>getArgument(1).write("{\"bomFormat\":\"CycloneDX\"}".getBytes());
            return null;
        }).when(cbomProjectionService).writeCbom(eq(ORG_ID), any());
        MockHttpServletResponse response = new MockHttpServletResponse();

        cbomController.downloadCbom(response);

        assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getHeader("Content-Disposition"))
                .contains("attachment")
                .contains("cbom.json");
        assertThat(response.getContentAsString()).contains("CycloneDX");
    }

    @Test
    void downloadCbom_serviceFailure_propagates() throws IOException {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-2", "user@test.com");
        doThrow(new IOException("connection reset")).when(cbomProjectionService).writeCbom(eq(ORG_ID), any());

        assertThatThrownBy(() -> cbomController.downloadCbom(new MockHttpServletResponse()))
                .isInstanceOf(IOException.class)
                .hasMessage("connection reset");
    }
}
