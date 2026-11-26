// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.agent.CertificateAuthoritiesResponse;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.agent.CertificateAuthorityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/** The CA list is scoped to the organization in the caller's token; there is no way to name another one. */
@ExtendWith(MockitoExtension.class)
class CertificateAuthorityControllerTest {

    @Mock
    private CertificateAuthorityService certificateAuthorityService;

    @InjectMocks
    private CertificateAuthorityController controller;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void listsOnlyTheTokensOrganization() {
        GatewayRequestContext.set(101, "7", "req-cas", "user@example.com");
        CertificateAuthoritiesResponse body = new CertificateAuthoritiesResponse(List.of());
        when(certificateAuthorityService.list(7L)).thenReturn(body);

        assertThat(controller.list().getBody()).isSameAs(body);

        verify(certificateAuthorityService).list(7L);
        verifyNoMoreInteractions(certificateAuthorityService);
    }

    @Test
    void withoutAnOrganizationInTheToken_isDenied() {
        GatewayRequestContext.set(101, null, "req-cas-noorg", "user@example.com");

        assertThatThrownBy(() -> controller.list()).isInstanceOf(AccessDeniedException.class);

        verifyNoInteractions(certificateAuthorityService);
    }
}
