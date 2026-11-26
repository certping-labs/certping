// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.dto.organization.UpdateOrganizationRequest;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.OrganizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OrganizationControllerErrorBranchesTest {

    private final OrganizationService organizationService = mock(OrganizationService.class);
    private final OrganizationController controller = new OrganizationController(organizationService);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    @Test
    void getOrganizationById_invalidIdentifier_throwsBadRequest() {
        assertThatThrownBy(() -> controller.getOrganizationById("bad-id"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("For input string");
    }

    @Test
    void updateOrganization_invalidIdentifier_throwsBadRequest() {
        assertThatThrownBy(() -> controller.updateOrganization("bad-id", new UpdateOrganizationRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("For input string");
    }

    @Test
    void deleteOrganization_invalidIdentifier_throwsBadRequest() {
        assertThatThrownBy(() -> controller.deleteOrganization("bad-id"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("For input string");
    }

    @Test
    void getOrganizationByDomain_scopeMismatch_throwsForbidden() {
        OrganizationDto organization = mock(OrganizationDto.class);

        when(organization.getDomain()).thenReturn("example.com");
        when(organizationService.getOrganizationById(1L)).thenReturn(organization);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                "user",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_ORGANIZATION_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        GatewayRequestContext.set(101, "1", "req-1", "user@example.com");

        assertThatThrownBy(() -> controller.getOrganizationByDomain("other.com"))
                .isInstanceOf(ForbiddenException.class)
                .hasMessageContaining("Access denied for requested organization domain");
    }
}
