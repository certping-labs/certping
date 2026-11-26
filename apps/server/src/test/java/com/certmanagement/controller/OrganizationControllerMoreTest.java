// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.dto.organization.UpdateOrganizationRequest;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.OrganizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationControllerMoreTest {

    @Mock private OrganizationService organizationService;

    private OrganizationController controller;

    private static final Long ORG_ID = 7L;

    @BeforeEach
    void setUp() {
        controller = new OrganizationController(organizationService);
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    private void asSuperAdmin() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("super", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));
    }

    private void asOrgUser() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "user@example.com");
    }

    private OrganizationDto orgDto() {
        return OrganizationDto.builder()
                .id(ORG_ID).name("Acme").domain("acme.com").slug("acme-corp").build();
    }

    @Test
    void createOrganization_returnsCreated() {
        OrganizationDto dto = orgDto();
        when(organizationService.createOrganization(dto)).thenReturn(dto);

        ResponseEntity<OrganizationDto> resp = controller.createOrganization(dto);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(resp.getBody()).isEqualTo(dto);
    }

    @Test
    void getOrganizationById_orgUser_resolvesAndReturns() {
        asOrgUser();
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(orgDto());

        assertThat(controller.getOrganizationById(String.valueOf(ORG_ID)).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void getOrganizationByDomain_superAdmin_delegatesDirectly() {
        asSuperAdmin();
        when(organizationService.getOrganizationByDomain("acme.com")).thenReturn(orgDto());

        assertThat(controller.getOrganizationByDomain("acme.com").getBody().getDomain()).isEqualTo("acme.com");
    }

    @Test
    void getOrganizationByDomain_orgUser_matchingDomain_returns() {
        asOrgUser();
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(orgDto());

        assertThat(controller.getOrganizationByDomain("acme.com").getBody().getDomain()).isEqualTo("acme.com");
    }

    @Test
    void getOrganizationByDomain_orgUser_mismatch_throwsForbidden() {
        asOrgUser();
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(orgDto());

        assertThatThrownBy(() -> controller.getOrganizationByDomain("other.com"))
                .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void getOrganizationBySlug_superAdmin_delegates() {
        asSuperAdmin();
        when(organizationService.getOrganizationBySlug("acme-corp")).thenReturn(orgDto());

        assertThat(controller.getOrganizationBySlug("acme-corp").getBody().getSlug()).isEqualTo("acme-corp");
    }

    @Test
    void getOrganizationBySlug_orgUser_mismatch_throwsForbidden() {
        asOrgUser();
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(orgDto());

        assertThatThrownBy(() -> controller.getOrganizationBySlug("other-slug"))
                .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void getOrganizationByName_superAdmin_delegates() {
        asSuperAdmin();
        when(organizationService.getOrganizationByName("Acme")).thenReturn(orgDto());

        assertThat(controller.getOrganizationByName("Acme").getBody().getName()).isEqualTo("Acme");
    }

    @Test
    void getOrganizationByName_orgUser_mismatch_throwsForbidden() {
        asOrgUser();
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(orgDto());

        assertThatThrownBy(() -> controller.getOrganizationByName("Other"))
                .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void getAllOrganizations_superAdmin_returnsAll() {
        asSuperAdmin();
        when(organizationService.getAllOrganizations()).thenReturn(List.of(orgDto()));

        assertThat(controller.getAllOrganizations().getBody()).hasSize(1);
    }

    @Test
    void getAllOrganizations_orgUser_returnsOwnOrgOnly() {
        asOrgUser();
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(orgDto());

        assertThat(controller.getAllOrganizations().getBody()).hasSize(1);
    }

    @Test
    void updateOrganization_orgUser_delegates() {
        asOrgUser();
        UpdateOrganizationRequest req = new UpdateOrganizationRequest();
        when(organizationService.updateOrganization(eq(ORG_ID), any())).thenReturn(orgDto());

        assertThat(controller.updateOrganization(String.valueOf(ORG_ID), req).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void deleteOrganization_orgUser_returnsNoContent() {
        asOrgUser();

        ResponseEntity<Void> resp = controller.deleteOrganization(String.valueOf(ORG_ID));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(organizationService).deleteOrganization(ORG_ID);
    }
}
