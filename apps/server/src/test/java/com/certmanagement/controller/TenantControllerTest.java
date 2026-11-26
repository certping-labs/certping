// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.OrganizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class OrganizationControllerTest {

    @AfterEach
    void cleanup() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void createOrganization_isProtectedBySuperAdminRole() throws Exception {
        Method method = OrganizationController.class.getMethod(
                "createOrganization", com.certmanagement.dto.organization.OrganizationDto.class);
        PreAuthorize preAuthorize = method.getAnnotation(PreAuthorize.class);

        assertThat(preAuthorize).isNotNull();
        assertThat(preAuthorize.value()).isEqualTo("hasRole('SUPER_ADMIN')");
    }

    @Test
    void deleteOrganization_callsServiceAndReturnsNoContent() {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("admin", null,
                        List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));

        OrganizationService organizationService = mock(OrganizationService.class);
        OrganizationController controller = new OrganizationController(organizationService);

        var response = controller.deleteOrganization("15");

        verify(organizationService).deleteOrganization(15L);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }
}
